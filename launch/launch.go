// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package launch provides functions and methods for LTI's tool launch.
package launch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
	"github.com/macewan-cs/lti/login"
)

// A Launch implements an external application's role in the LTI specification's launch flow.
type Launch struct {
	cfg  datastore.Config
	next http.HandlerFunc
}

// ContextKeyType is used as the key to store the launch ID in the request context.
type ContextKeyType string

// ContextKey is the actual value used for the context key.
const ContextKey = ContextKeyType("LaunchID")

var (
	maximumResourceLinkIDLength = 255
	supportedLTIVersion         = "1.3.0"
	launchIDPrefix              = "lti1p3-launch-"
)

// New creates a *Launch, which implements the http.Handler interface for launching a tool.
func New(cfg datastore.Config, next http.HandlerFunc) *Launch {
	launch := Launch{
		cfg:  cfg,
		next: next,
	}

	if launch.cfg.LaunchData == nil {
		launch.cfg.LaunchData = nonpersistent.DefaultStore
	}
	if launch.cfg.Registrations == nil {
		launch.cfg.Registrations = nonpersistent.DefaultStore
	}
	if launch.cfg.Nonces == nil {
		launch.cfg.Nonces = nonpersistent.DefaultStore
	}

	return &launch
}

// ServeHTTP performs validations according the OIDC launch flow modified for use by the IMS Global LTI v1p3
// specifications. State is found in a user agent cookie and the POST body. Nonce is found embedded in the id_token and
// in a datastore.
func (l *Launch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		rawToken      []byte
		statusCode    int
		err           error
		registration  datastore.Registration
		verifiedToken jwt.Token
		launchData    json.RawMessage
	)

	if rawToken, statusCode, err = getRawToken(r); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if registration, statusCode, err = validateRegistration(rawToken, l, r); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if verifiedToken, statusCode, err = validateSignature(rawToken, registration, r); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateState(r); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateClientID(verifiedToken, registration); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateNonceAndTargetLinkURI(verifiedToken, l); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateDeploymentID(verifiedToken, l); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateVersionAndMessageType(verifiedToken); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if statusCode, err = validateResourceLink(verifiedToken); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if launchData, statusCode, err = getLaunchData(rawToken); err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	// Store the Launch data under a unique Launch ID for future reference.
	launchID := launchIDPrefix + uuid.New().String()
	l.cfg.LaunchData.StoreLaunchData(launchID, launchData)

	// Put the launch ID in the request context for subsequent handlers.
	r = r.WithContext(contextWithLaunchID(r.Context(), launchID))

	l.next(w, r)
}

// getRawToken gets the OIDC id_token.
func getRawToken(r *http.Request) ([]byte, int, error) {
	// Decode token and check for JWT format errors without verification. An external keyset is needed for verification.
	idToken := []byte(r.FormValue("id_token"))
	_, err := jwt.Parse(idToken)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("get raw token: %w", err)
	}

	return idToken, http.StatusOK, nil
}

// validateRegistration finds the registration by the issuer of the token.
func validateRegistration(rawToken []byte, l *Launch, r *http.Request) (datastore.Registration, int, error) {
	token, err := jwt.Parse(rawToken)
	if err != nil {
		return datastore.Registration{}, http.StatusBadRequest, fmt.Errorf("validate registration: %w", err)
	}

	issuer := token.Issuer()
	clientID := token.Audience()[0]
	registration, err := l.cfg.Registrations.FindRegistrationByIssuerAndClientID(issuer, clientID)
	if err != nil {
		if err == datastore.ErrRegistrationNotFound {
			return datastore.Registration{}, http.StatusBadRequest, fmt.Errorf("no registration found for iss %s", issuer)
		}

		return datastore.Registration{}, http.StatusInternalServerError, fmt.Errorf("validate registration: %w", err)
	}

	return registration, http.StatusOK, nil
}

// validateSignature checks the authenticity of the token.
func validateSignature(rawToken []byte, registration datastore.Registration, r *http.Request) (jwt.Token, int, error) {
	// Get keyset from the Platform for verification.
	keyset, err := jwk.Fetch(context.Background(), registration.KeysetURI.String())
	if err != nil {
		// Since the KeysetURI is part of the registration, a failure to retrieve it should be reported as an
		// internal server error.
		return nil, http.StatusInternalServerError, fmt.Errorf("validate signature: %w", err)
	}

	// Perform the signature check.
	verifiedToken, err := jwt.Parse(rawToken, jwt.WithKeySet(keyset))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("validate signature: %w", err)
	}

	return verifiedToken, http.StatusOK, nil
}

// validateState checks the state cookie against the state query value returned by the Platform.
func validateState(r *http.Request) (int, error) {
	stateCookie, err := r.Cookie(login.StateCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		stateCookie, err = r.Cookie(login.LegacyStateCookieName)
	}
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("cannot get cookie from request: %w", err)
	}

	state := r.FormValue("state")
	if stateCookie.Value != state {
		return http.StatusBadRequest, errors.New("state validation failed")
	}

	return http.StatusOK, nil
}

// validateClientID checks that the claimed client ID (aud) is listed for the claimed issuer.
func validateClientID(verifiedToken jwt.Token, registration datastore.Registration) (int, error) {
	audience := verifiedToken.Audience()
	found := contains(registration.ClientID, audience)
	if !found {
		return http.StatusBadRequest, errors.New("client ID not registered for this issuer")
	}

	return http.StatusOK, nil
}

// validateNonceAndTargetLinkURI verifies that the TargetLinkURI provided during the initial (login) auth request and
// the id_token matches, and in the process, it checks that the nonce also exists.
func validateNonceAndTargetLinkURI(verifiedToken jwt.Token, l *Launch) (int, error) {
	targetLinkURI, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/target_link_uri")
	if !ok {
		return http.StatusBadRequest, errors.New("target link URI not found in request")
	}

	nonce, ok := verifiedToken.Get("nonce")
	if !ok {
		return http.StatusBadRequest, errors.New("nonce not found in request")
	}
	err := l.cfg.Nonces.TestAndClearNonce(nonce.(string), targetLinkURI.(string))
	if err != nil {
		if err == datastore.ErrNonceNotFound || err == datastore.ErrNonceTargetLinkURIMismatch {
			return http.StatusBadRequest, err
		}

		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// validateDeploymentID verifies that the deployment ID exists under the issuer.
func validateDeploymentID(verifiedToken jwt.Token, l *Launch) (int, error) {
	deploymentID, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
	if !ok {
		return http.StatusBadRequest, errors.New("deployment not found in request")
	}

	_, err := l.cfg.Registrations.FindDeployment(verifiedToken.Issuer(), deploymentID.(string))
	if err != nil {
		if err == datastore.ErrDeploymentNotFound {
			return http.StatusBadRequest, err
		}

		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// validateVersionAndMessageType checks for a valid version and message type. Only 'Resource link launch request'
// (LtiResourceLinkRequest) is currently supported.
func validateVersionAndMessageType(verifiedToken jwt.Token) (int, error) {
	ltiVersion, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/version")
	if !ok {
		return http.StatusBadRequest, errors.New("LTI version not found in request")
	}
	if ltiVersion != supportedLTIVersion {
		return http.StatusBadRequest, errors.New("compatible version not found in request")
	}

	messageType, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/message_type")
	if !ok {
		return http.StatusBadRequest, errors.New("message type not found in request")
	}
	if messageType.(string) != "LtiResourceLinkRequest" {
		return http.StatusBadRequest, errors.New("supported message type not found in request")
	}

	return http.StatusOK, nil
}

// validateResourceLink verifies the resource link and ID.
func validateResourceLink(verifiedToken jwt.Token) (int, error) {
	rawResourceLink, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/resource_link")
	if !ok {
		return http.StatusBadRequest, errors.New("resource link not found in request")
	}

	resourceLink, ok := rawResourceLink.(map[string]interface{})
	if !ok {
		return http.StatusBadRequest, errors.New("resource link improperly formatted")
	}

	resourceLinkID, ok := resourceLink["id"]
	if !ok {
		return http.StatusBadRequest, errors.New("resource link ID not found")
	}
	if len(resourceLinkID.(string)) > maximumResourceLinkIDLength {
		return http.StatusBadRequest, fmt.Errorf("resource link ID exceeds maximum length (%d)", maximumResourceLinkIDLength)
	}

	return http.StatusOK, nil
}

// getLaunchData parses the id_token to get JWT payload for storage.
func getLaunchData(rawToken []byte) (json.RawMessage, int, error) {
	if len(rawToken) == 0 {
		return nil, http.StatusBadRequest, errors.New("received empty raw token argument")
	}
	rawTokenParts := strings.SplitN(string(rawToken), ".", 3)
	payload, err := base64.RawURLEncoding.DecodeString(rawTokenParts[1])
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("get launch data: %w", err)
	}

	return json.RawMessage(payload), http.StatusOK, nil
}

// contains returns whether a string exists in a []string.
func contains(n string, s []string) bool {
	for _, v := range s {
		if v == n {
			return true
		}
	}

	return false
}

// contextWithLaunchID puts the launch ID into the given context.
func contextWithLaunchID(ctx context.Context, launchID string) context.Context {
	key := ContextKey

	return context.WithValue(ctx, key, launchID)
}
