// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package launch

import (
	"context"
	"fmt"
	"net/http"

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

// ServeHTTP
//
// Note: The handler must compare the "state" (generated and set in login) in a cookie with the "state" in the POST body.
// Note: The handler must TestAndClear the "nonce" (verifying "true"). This nonce can be found in the POST body.
// Note: Generate and add launch_id to req context.
func (l *Launch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idToken := []byte(r.FormValue("id_token"))
	token, err := jwt.Parse(idToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	issuer := token.Issuer()
	registration, err := l.cfg.Registrations.FindRegistrationByIssuer(issuer)
	if err != nil {
		http.Error(w, fmt.Sprintf("no registration found for issuer %s", issuer), http.StatusBadRequest)
		return
	}
	// Get keyset for verification.
	keyset, err := jwk.Fetch(context.Background(), registration.KeysetURI.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Verification (signature check).
	verifiedToken, err := jwt.Parse(idToken, jwt.WithKeySet(keyset))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// State.
	state := r.FormValue("state")
	stateCookie, err := r.Cookie("stateCookie")
	if err != nil {
		http.Error(w, "state cookie not found", http.StatusBadRequest)
		return
	}
	if stateCookie.Value != state {
		http.Error(w, "state validation failed", http.StatusBadRequest)
	}
	// Nonce and target link URI.
	targetLinkURI, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/target_link_uri")
	if !ok {
		http.Error(w, "target link uri not found in request", http.StatusBadRequest)
		return
	}
	nonce, ok := verifiedToken.Get("nonce")
	if !ok {
		http.Error(w, "nonce not found in request", http.StatusBadRequest)
		return
	}
	found, err := l.cfg.Nonces.TestAndClearNonce(nonce.(string), targetLinkURI.(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Aud.
	aud := verifiedToken.Audience()
	found = contains(registration.ClientID, aud)
	if !found {
		http.Error(w, "client id not registered for this issuer", http.StatusBadRequest)
		return
	}
	// Deployment ID.
	deploymentID, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/deployment_id")
	if !ok {
		http.Error(w, "deployment not found in request", http.StatusBadRequest)
		return
	}
	_, err = l.cfg.Registrations.FindDeployment(issuer, deploymentID.(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// LTI version.
	ltiVersion, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/version")
	if !ok {
		http.Error(w, "lti version not found in request", http.StatusBadRequest)
		return
	}
	if ltiVersion != "1.3.0" {
		http.Error(w, "compatible version not found in request", http.StatusBadRequest)
		return
	}
	// Message Type. Only 'Resource link launch request' (LtiResourceLinkRequest) type is currently supported.
	messageType, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/message_type")
	if !ok {
		http.Error(w, "message type not found in request", http.StatusBadRequest)
		return
	}
	if messageType.(string) != "LtiResourceLinkRequest" {
		http.Error(w, "supported message type not found in request", http.StatusBadRequest)
		return
	}
	// Resource link ID.
	resourceLink, ok := verifiedToken.Get("https://purl.imsglobal.org/spec/lti/claim/resource_link")
	if !ok {
		http.Error(w, "lti version not found in request", http.StatusBadRequest)
		return
	}
	switch resourceLink.(type) {
	case map[string]interface{}:
		resourceMap := resourceLink.(map[string]interface{})
		resourceLinkID, ok := resourceMap["id"]
		if !ok {
			http.Error(w, "resource id not found", http.StatusBadRequest)
			return
		}
		if len(resourceLinkID.(string)) > maximumResourceLinkIDLength {
			http.Error(w, fmt.Sprintf("exceeds maximum length (%d)", maximumResourceLinkIDLength), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "resource link improperly formatted", http.StatusBadRequest)
		return
	}
	// Launch ID.
	launchID := "lti1p3-launch-" + uuid.New().String()
	fmt.Println(launchID)
}

func contains(n string, s []string) bool {
	for _, v := range s {
		if v == n {
			return true
		}
	}
	return false
}

// The exported method Validate makes several unexported checks.
func (l *Launch) Validate(r *http.Request) {
}

// Cookie check.
func validateState(r *http.Request) error {
	return nil
}

// Nonce check.
func validateNonce(r *http.Request) error {
	return nil
}

// Find Registration by issuer, confirm id_token 'aud' claim matches registered ClientID.
func validateRegistration(r *http.Request) error {
	return nil
}

// Signature check, message authenticity check.
func validateJWTSignature(r *http.Request) error {
	return nil
}

// Deployment_ID must exist under the issuer.
func validateDeployment(r *http.Request) error {
	return nil
}

// Check for a valid message type.
func validateMessageType(r *http.Request) error {
	return nil
}
