// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package login

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/macewan-cs/lti/datastore"
)

// Set up a test Registration.
func getRegistration() datastore.Registration {
	authTokenURI, _ := url.Parse("https://platform.tld/instance/token")
	authLoginURI, _ := url.Parse("https://platform.tld/instance/auth")
	keysetURI, _ := url.Parse("https://platform.tld/instance/keyset")
	launchURI, _ := url.Parse("https://tool.tld/launcher")

	return datastore.Registration{
		Issuer:        "https://platform.tld/instance",
		ClientID:      "abcdef123456",
		AuthTokenURI:  authTokenURI,
		AuthLoginURI:  authLoginURI,
		KeysetURI:     keysetURI,
		TargetLinkURI: launchURI,
	}
}

// Set up a test POST request body.
func getPostBody() []byte {
	return []byte("iss=https://platform.tld/instance" +
		"&target_link_uri=https://tool.tld" +
		"&login_hint=1" +
		"&lti_message_hint=123" +
		"&client_id=abcdef123456" +
		"&lti_deployment_id=1")
}

// Test instantiation.
func TestNew(t *testing.T) {
	actual := New(Config{})
	if actual == nil {
		t.Fatal("got nil, want non-nil")
	}
}

// Test the validate checks with appropriately malformed requests.
func TestValidate(t *testing.T) {
	login := New(Config{})
	login.cfg.Registrations.StoreRegistration(getRegistration())

	r := httptest.NewRequest(http.MethodPost, "https://tool.tld/login", bytes.NewReader([]byte("")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	expected := "issuer not found in login request"
	_, actual := login.validate(r)
	if actual.Error() != expected {
		t.Fatalf("validate error: %v", actual)
	}

	r = httptest.NewRequest(http.MethodPost, "https://tool.tld/login", bytes.NewReader(
		[]byte("iss=https://platform.tld/instance")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	expected = "login hint not found in login request"
	_, actual = login.validate(r)
	if actual.Error() != expected {
		t.Fatalf("validate error: %v", actual)
	}

	r = httptest.NewRequest(http.MethodPost, "https://tool.tld/login", bytes.NewReader(
		[]byte("iss=https://platform.tld/instance&login_hint=1")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	expected = "target link uri not found in login request"
	_, actual = login.validate(r)
	if actual.Error() != expected {
		t.Fatalf("validate error: %v", actual)
	}

	r = httptest.NewRequest(http.MethodPost, "https://tool.tld/login", bytes.NewReader(
		[]byte("iss=https://platform.tld/instance&login_hint=1&target_link_uri=https://tool.tld")))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, actual = login.validate(r)
	if actual != nil {
		t.Fatalf("validate error: %v", actual)
	}
}

// Test the RedirectURI method.
func TestRedirectURI(t *testing.T) {
	login := New(Config{})
	login.cfg.Registrations.StoreRegistration(getRegistration())

	r := httptest.NewRequest(http.MethodPost, "https://tool.tld/login", bytes.NewReader(getPostBody()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	redirect, cookie, err := login.RedirectURI(r)
	if err != nil {
		t.Fatalf("redirect uri error: %v", err)
	}
	redirectURI, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("redirect uri parse error: %v", err)
	}
	if cookie.Name != "stateCookie" || cookie.Value != redirectURI.Query().Get("state") {
		t.Fatalf("redirect uri cookie error")
	}
}
