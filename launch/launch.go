// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package launch

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

type Config struct {
	LaunchDatas   datastore.LaunchDataStorer
	AccessTokens  datastore.AccessTokenStorer
	Registrations datastore.RegistrationStorer
	Nonces        datastore.NonceStorer
}

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

type Launch struct {
	cfg Config
	//key			some.KeyType
}

// ServeHTTP
//
// Note: The handler must compare the "state" (generated and set in login) in a cookie with the "state" in the POST body.
// Note: The handler must TestAndClear the "nonce" (verifying "true"). This nonce can be found in the POST body.
// Note: Generate and add launch_id to req context.
func (l *Launch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	fmt.Println(string(dump))
}

// The exported method Validate makes several unexported checks.
func (l *Launch) Validate(r *http.Request) {

}

// Cookie check.
func validateState(r *http.Request) error {
	return nil
}

// JWT format check.
func validateJWTFormat(r *http.Request) error {
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
