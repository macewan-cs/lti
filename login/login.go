// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package login provides functions and methods for LTI's modified OpenID Connect login flow.
package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

// New creates a new login object. If the passed Config has zero-value store interfaces, fall back on the in-memory
// nonpersistent.DefaultStore.
func New(cfg datastore.Config) *Login {
	login := Login{
		cfg: cfg,
	}

	if login.cfg.Registrations == nil {
		login.cfg.Registrations = nonpersistent.DefaultStore
	}
	if login.cfg.Nonces == nil {
		login.cfg.Nonces = nonpersistent.DefaultStore
	}

	return &login
}

// A Login implements an http.Handler that can be easily associated with a tool URI such as /services/lti/login/.
type Login struct {
	cfg datastore.Config
}

// RedirectURI extracts the form data from the initial login request and returns a auth redirect URI and state cookie.
// The login must cache the "nonce" locally and include it in the response.
func (l *Login) RedirectURI(r *http.Request) (string, http.Cookie, error) {
	registration, err := l.validate(r)
	if err != nil {
		return "", http.Cookie{}, err
	}

	// Generate state and state cookie.
	state := "state-" + uuid.New().String()
	stateCookie := http.Cookie{
		Name:  "stateCookie",
		Value: state,
		Path:  registration.TargetLinkURI.EscapedPath(),
	}

	// Generate and store nonce.
	nonce := uuid.New().String()
	err = l.cfg.Nonces.StoreNonce(nonce, registration.TargetLinkURI.String())
	if err != nil {
		return "", http.Cookie{}, err
	}

	// Build auth response to initial login request.
	values := url.Values{}
	values.Set("scope", "openid")
	values.Set("response_type", "id_token")
	values.Set("response_mode", "form_post")
	values.Set("prompt", "none")
	values.Set("client_id", registration.ClientID)
	values.Set("redirect_uri", registration.TargetLinkURI.String())
	values.Set("state", state)
	values.Set("nonce", nonce)
	values.Set("login_hint", r.FormValue("login_hint"))

	// Pass back the message hint if received.
	if r.FormValue("lti_message_hint") != "" {
		values.Set("lti_message_hint", r.FormValue("lti_message_hint"))
	}

	redirectURI := registration.AuthLoginURI
	redirectURI.RawQuery = values.Encode()
	return redirectURI.String(), stateCookie, nil
}

// JSRedirect will return JS code to perform the redirect.
func (l *Login) JSRedirect(w http.ResponseWriter, r *http.Request) (string, error) {
	redirect, stateCookie, err := l.RedirectURI(r)
	if err != nil {
		return "", err
	}

	return "JS redirect code using: " + redirect + stateCookie.Name, nil
}

// ServeHTTP makes Login an http.Handler so that it can easily be associated with tool URI, e.g., /services/lti/login/.
// The handler must set the "state" in a cookie (in addition to including it in the response) and the two will be
// compared in the launch.
func (l *Login) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirectURI, stateCookie, err := l.RedirectURI(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &stateCookie)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// validate checks for the presence of the issuer and login_hint, and existence of a registration for that issuer.
func (l *Login) validate(r *http.Request) (datastore.Registration, error) {
	// Validate issuer.
	if r.FormValue("iss") == "" {
		return datastore.Registration{}, errors.New("issuer not found in login request")
	}

	// Validate login hint.
	if r.FormValue("login_hint") == "" {
		return datastore.Registration{}, errors.New("login hint not found in login request")
	}

	// Validate target link uri.
	if r.FormValue("target_link_uri") == "" {
		return datastore.Registration{}, errors.New("target link uri not found in login request")
	}

	// Find Registration by issuer and/or client ID.
	registration, err := l.cfg.Registrations.FindRegistrationByIssuerAndClientID(r.FormValue("iss"), r.FormValue("client_id"))
	if err != nil {
		return datastore.Registration{}, err
	}

	return registration, nil
}
