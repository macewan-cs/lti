// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package nonpersistent

import (
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/macewan-cs/lti/datastore"
)

func TestNew(t *testing.T) {
	actual := New()
	if actual == nil {
		t.Fatal("got nil, want non-nil")
	}
}

func TestStoreAndFindRegistrationByIssuer(t *testing.T) {
	issuer := "https://test-issuer"
	authTokenURI, _ := url.Parse("https://domain.tld/token")
	authLoginURI, _ := url.Parse("https://domain.tld/auth")
	keysetURI, _ := url.Parse("https://domain.tld/keyset")
	targetLinkURI, _ := url.Parse("https://domain.tld/launcher")

	registration := datastore.Registration{
		Issuer:        issuer,
		ClientID:      "abcdef123456",
		AuthTokenURI:  authTokenURI,
		AuthLoginURI:  authLoginURI,
		KeysetURI:     keysetURI,
		TargetLinkURI: targetLinkURI,
	}

	npStore := New()

	err := npStore.StoreRegistration(registration)
	if err != nil {
		t.Fatalf("store registration error: %v", err)
	}

	_, err = npStore.FindRegistrationByIssuer("")
	if err == nil {
		t.Error("error not reported for empty issuer")
	}

	_, err = npStore.FindRegistrationByIssuer("unknown" + issuer)
	if err != datastore.ErrRegistrationNotFound {
		t.Error("unexpected error value for nonexistent issuer")
	}

	actual, err := npStore.FindRegistrationByIssuer(issuer)
	if err != nil {
		t.Fatalf("find registration error: %v", err)
	}

	if actual != registration {
		t.Fatal("found registration does not match stored registration")
	}
}

func TestStoreAndFindDeploymentByDeploymentID(t *testing.T) {
	issuer := "test-issuer"
	deploymentID := "1"
	expected := datastore.Deployment{DeploymentID: deploymentID}

	npStore := New()

	err := npStore.StoreDeployment("", deploymentID)
	if err == nil {
		t.Error("error not reported for empty issuer")
	}

	err = npStore.StoreDeployment(issuer, "")
	if err == nil {
		t.Error("error not reported for empty deployment ID")
	}

	err = npStore.StoreDeployment(issuer, deploymentID)
	if err != nil {
		t.Fatalf("store deployment error: %v", err)
	}

	actual, err := npStore.FindDeployment(issuer, deploymentID)
	if err != nil {
		t.Fatalf("find deployment error: %v", err)
	}
	// StoreDeployment accepts a string, not a datastore.Deployment, so the retrieved object should be deeply equal.
	equal := reflect.DeepEqual(expected, actual)
	if !equal {
		t.Fatal("found deployment does not match stored deployment")
	}

	_, err = npStore.FindDeployment("", deploymentID)
	if err == nil {
		t.Error("error not reported for empty issuer")
	}

	_, err = npStore.FindDeployment(issuer, "")
	if err == nil {
		t.Error("error not reported for invalid deployment ID")
	}

	_, err = npStore.FindDeployment(issuer, "unknown"+deploymentID)
	if err != datastore.ErrDeploymentNotFound {
		t.Error("unexpected error value for nonexistent deployment")
	}
}

func TestStoreAndTestAndClearNonce(t *testing.T) {
	issuer := "test-issuer"
	nonce := "dGVzdC1ub25jZQ=="

	npStore := New()

	err := npStore.StoreNonce("", issuer)
	if err == nil {
		t.Error("error not reported for empty nonce")
	}

	err = npStore.StoreNonce(nonce, "")
	if err == nil {
		t.Error("error not report for empty issuer")
	}

	err = npStore.StoreNonce(nonce, issuer)
	if err != nil {
		t.Fatalf("store nonce error: %v", err)
	}

	err = npStore.TestAndClearNonce(nonce, issuer)
	if err != nil {
		t.Fatalf("test and clear nonce error: %v", err)
	}

	// Test the double-clearing of the nonce.
	err = npStore.TestAndClearNonce(nonce, issuer)
	if err != datastore.ErrNonceNotFound {
		t.Fatalf("test and clear nonce error: %v", err)
	}

	err = npStore.TestAndClearNonce("unknown"+nonce, issuer)
	if err != datastore.ErrNonceNotFound {
		t.Error("unexpected error value for nonexistent nonce")
	}
}

func TestStoreAccessToken(t *testing.T) {
	testToken := datastore.AccessToken{
		TokenURI:   "https://domain.tld/token",
		ClientID:   "abcdef123456",
		Scopes:     []string{"https://scope/1.readonly", "https://scope/2.delete"},
		Token:      "123456789abcdef",
		ExpiryTime: time.Now().Add(-time.Minute * 30),
	}
	npStore := New()

	testToken.TokenURI = ""
	err := npStore.StoreAccessToken(testToken)
	if err.Error() != "received empty tokenURI" {
		t.Error("error not reported for empty tokenURI")
	}
	testToken.TokenURI = "https://domain.tld/token"

	testToken.ClientID = ""
	err = npStore.StoreAccessToken(testToken)
	if err.Error() != "received empty clientID" {
		t.Error("error not reported for empty clientID")
	}
	testToken.ClientID = "abcdef123456"

	testToken.Scopes = []string{}
	err = npStore.StoreAccessToken(testToken)
	if err.Error() != "received empty scopes" {
		t.Error("error not reported for empty scopes")
	}
	testToken.Scopes = []string{"https://scope/1.readonly", "https://scope/2.delete"}

	testToken.Token = ""
	err = npStore.StoreAccessToken(testToken)
	if err.Error() != "received empty accessToken" {
		t.Error("error not reported for empty token string")
	}
	testToken.Token = "123456789abcdef"

	testToken.ExpiryTime = time.Time{}
	err = npStore.StoreAccessToken(testToken)
	if err.Error() != "received empty expiry time" {
		t.Error("error not reported for empty expiry time")
	}
	testToken.ExpiryTime = time.Now().Add(-time.Minute * 30)

	err = npStore.StoreAccessToken(testToken)
	if err != nil {
		t.Fatal("access token storage failed")
	}
}

func TestFindAccessToken(t *testing.T) {
	testToken := datastore.AccessToken{
		TokenURI:   "https://domain.tld/token",
		ClientID:   "abcdef123456",
		Scopes:     []string{"https://scope/1.readonly", "https://scope/2.delete"},
		Token:      "123456789abcdef",
		ExpiryTime: time.Now().Add(-time.Minute * 30),
	}
	npStore := New()

	testToken.TokenURI = ""
	_, err := npStore.FindAccessToken(testToken)
	if err.Error() != "received empty tokenURI" {
		t.Error("error not reported for empty tokenURI")
	}
	testToken.TokenURI = "https://domain.tld/token"

	testToken.ClientID = ""
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "received empty clientID" {
		t.Error("error not reported for empty clientID")
	}
	testToken.ClientID = "abcdef123456"

	testToken.Scopes = []string{}
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "received empty scopes" {
		t.Error("error not reported for empty scopes")
	}
	testToken.Scopes = []string{"https://scope/1.readonly", "https://scope/2.delete"}

	testToken.Token = ""
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "received empty accessToken" {
		t.Error("error not reported for empty token string")
	}
	testToken.Token = "123456789abcdef"

	testToken.ExpiryTime = time.Time{}
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "received empty expiry time" {
		t.Error("error not reported for empty expiry time")
	}
	testToken.ExpiryTime = time.Now().Add(-time.Minute * 30)

	testToken.ClientID = "nonexistent"
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "no access token found" {
		t.Error("error not reported for no token found")
	}
	testToken.ClientID = "abcdef123456"

	err = npStore.StoreAccessToken(testToken)
	if err != nil {
		t.Fatal("could not store token for find test")
	}
	_, err = npStore.FindAccessToken(testToken)
	if err.Error() != "access token has expired" {
		t.Fatal("error not reported for expired token")
	}

	testToken.ExpiryTime = time.Now().Add(time.Minute * 30).Round(0)
	err = npStore.StoreAccessToken(testToken)
	if err != nil {
		t.Fatal("could not store token for find test")
	}
	actual, err := npStore.FindAccessToken(testToken)
	if err != nil {
		t.Fatal("unexpected error reported")
	}
	equal := reflect.DeepEqual(testToken, actual)
	if !equal {
		t.Fatal("found token does not match test token")
	}
}
