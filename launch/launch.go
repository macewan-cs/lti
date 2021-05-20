// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

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
)

type Config struct {
	LaunchDatas   datastore.LaunchDataStorer
	AccessTokens  datastore.AccessTokenStorer
	Registrations datastore.RegistrationStorer
	Nonces        datastore.NonceStorer
}

type Launch struct {
	cfg Config
}

var maximumResourceLinkIDLength = 255

func New(cfg Config) *Launch {
	launch := Launch{}

	if cfg.LaunchDatas == nil {
		launch.cfg.LaunchDatas = nonpersistent.DefaultStore
	}
	if cfg.AccessTokens == nil {
		launch.cfg.AccessTokens = nonpersistent.DefaultStore
	}
	if cfg.Registrations == nil {
		launch.cfg.Registrations = nonpersistent.DefaultStore
	}
	if cfg.Nonces == nil {
		launch.cfg.Nonces = nonpersistent.DefaultStore
	}

	return &launch
}

// ServeHTTP perfoms validations according the OIDC launch flow modified for use by the IMS Global LTI v1p3
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
	launchID := "lti1p3-launch-" + uuid.New().String()
	l.cfg.LaunchDatas.StoreLaunchData(launchID, launchData)
}

// Get the OICD id_token.
func getRawToken(r *http.Request) ([]byte, int, error) {
	idToken := []byte(r.FormValue("id_token"))
	// Decode token and check for JWT format errors without verification. An external keyset is needed for verification.
	_, err := jwt.Parse(idToken)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return idToken, http.StatusOK, nil
}

// Find Registration by issuer, confirm id_token 'aud' claim matches registered ClientID.
func validateRegistration(rawToken []byte, l *Launch, r *http.Request) (datastore.Registration, int, error) {
	token, err := jwt.Parse(rawToken)
	if err != nil {
		return datastore.Registration{}, http.StatusInternalServerError, err
	}

	issuer := token.Issuer()
	registration, err := l.cfg.Registrations.FindRegistrationByIssuer(issuer)
	if err != nil {
		return datastore.Registration{}, http.StatusBadRequest, fmt.Errorf("no registration found for iss %s", issuer)
	}

	return registration, http.StatusOK, nil
}

// Signature check, message authenticity check.
func validateSignature(rawToken []byte, registration datastore.Registration, r *http.Request) (jwt.Token, int, error) {
	// Get keyset from the Platform for verification.
	keyset, err := jwk.Fetch(context.Background(), registration.KeysetURI.String())
	if err != nil {
		return nil, http.StatusNotFound, err
	}

	// Perform the signature check.
	verifiedToken, err := jwt.Parse(rawToken, jwt.WithKeySet(keyset))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return verifiedToken, http.StatusOK, nil
}

// Check the state cookie against the state query value returned by the Platform.
func validateState(r *http.Request) (int, error) {
	state := r.FormValue("state")
	stateCookie, err := r.Cookie("stateCookie")
	if err != nil {
		return http.StatusBadRequest, errors.New("state cookie not found")
	}
	if stateCookie.Value != state {
		return http.StatusBadRequest, errors.New("state validation failed")
	}

	return http.StatusOK, nil
}

// Check that the claimed client ID (aud) is listed for the claimed issuer.
func validateClientID(verifiedToken jwt.Token, registration datastore.Registration) (int, error) {
	audience := verifiedToken.Audience()
	found := contains(registration.ClientID, audience)
	if !found {
		return http.StatusBadRequest, errors.New("client id not registered for this issuer")
	}

	return http.StatusOK, nil
}

// TargetLinkURI must be verified to match between the initial (login) auth request and the id_token, and therefore
// serves as a value for incidental verification while also checking whether the nonce key exists.
func validateNonceAndTargetLinkURI(verifiedToken jwt.Token, l *Launch) (int, error) {
	targetLinkURI, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/target_link_uri")
	if !ok {
		return http.StatusBadRequest, errors.New("target link uri not found in request")
	}
	nonce, ok := verifiedToken.Get("nonce")
	if !ok {
		return http.StatusBadRequest, errors.New("nonce not found in request")
	}
	found, err := l.cfg.Nonces.TestAndClearNonce(nonce.(string), targetLinkURI.(string))
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if !found {
		return http.StatusBadRequest, err
	}

	return http.StatusOK, nil
}

// Deployment ID must exist under the issuer.
func validateDeploymentID(verifiedToken jwt.Token, l *Launch) (int, error) {
	// Deployment ID.
	deploymentID, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
	if !ok {
		return http.StatusBadRequest, errors.New("deployment not found in request")
	}
	_, err := l.cfg.Registrations.FindDeployment(verifiedToken.Issuer(), deploymentID.(string))
	if err != nil {
		return http.StatusBadRequest, err
	}

	return http.StatusOK, nil
}

// Check for valid version and message type. Only 'Resource link launch request' (LtiResourceLinkRequest) is currently
// supported.
func validateVersionAndMessageType(verifiedToken jwt.Token) (int, error) {
	ltiVersion, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/version")
	if !ok {
		return http.StatusBadRequest, errors.New("lti version not found in request")
	}
	if ltiVersion != "1.3.0" {
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

// Check resource link and ID.
func validateResourceLink(verifiedToken jwt.Token) (int, error) {
	resourceLink, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/resource_link")
	if !ok {
		return http.StatusBadRequest, errors.New("lti version not found in request")
	}
	resourceLinkMap, ok := resourceLink.(map[string]interface{})
	if !ok {
		return http.StatusBadRequest, errors.New("resource link improperly formatted")
	}
	resourceLinkID, ok := resourceLinkMap["id"]
	if !ok {
		return http.StatusBadRequest, errors.New("resource id not found")
	}
	if len(resourceLinkID.(string)) > maximumResourceLinkIDLength {
		return http.StatusBadRequest, fmt.Errorf("exceeds maximum length (%d)", maximumResourceLinkIDLength)
	}

	return http.StatusOK, nil
}

// Parse the id_token to get JWT payload for storage.
func getLaunchData(rawToken []byte) (json.RawMessage, int, error) {
	if len(rawToken) == 0 {
		return nil, http.StatusInternalServerError, errors.New("received empty raw token argument")
	}
	rawTokenParts := strings.SplitN(string(rawToken), ".", 3)
	payload, err := base64.RawURLEncoding.DecodeString(rawTokenParts[1])
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return json.RawMessage(payload), http.StatusOK, nil
}

// Check if a string exists in a []string.
func contains(n string, s []string) bool {
	for _, v := range s {
		if v == n {
			return true
		}
	}
	return false
}
