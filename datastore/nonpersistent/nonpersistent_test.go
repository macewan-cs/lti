// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package nonpersistent

import (
	"net/url"
	"reflect"
	"testing"

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
	// StoreDeployment accepts a string, not a datastore.Deployment, so the retrieved object should be only deeply
	// equal.
	if equal := reflect.DeepEqual(expected, actual); !equal {
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

func TestStoreAndFindAccessToken(t *testing.T) {
	tokenURI := "https://domain.tld/token"
	clientID := "abcdef123456"
	scopes := []string{"https://scope/1.readonly", "https://scope/2.delete"}
	expected := "aaaa1.bbbb2.cccc3"

	npStore := New()

	err := npStore.StoreAccessToken("", clientID, scopes, expected)
	if err.Error() != "received empty tokenURI argument" {
		t.Error("error not reported for empty tokenURI")
	}
	err = npStore.StoreAccessToken(tokenURI, "", scopes, expected)
	if err.Error() != "received empty clientID argument" {
		t.Error("error not reported for empty clientID")
	}
	err = npStore.StoreAccessToken(tokenURI, clientID, []string{}, expected)
	if err.Error() != "received empty scopes argument" {
		t.Error("error not reported for empty scopes")
	}
	err = npStore.StoreAccessToken(tokenURI, clientID, scopes, "")
	if err.Error() != "received empty accessToken argument" {
		t.Error("error not reported for empty token string")
	}

	err = npStore.StoreAccessToken(tokenURI, clientID, scopes, expected)
	if err != nil {
		t.Fatal("access token storage failed")
	}

	_, err = npStore.FindAccessToken("", clientID, scopes)
	if err.Error() != "received empty tokenURI argument" {
		t.Error("error not reported for empty tokenURI")
	}
	_, err = npStore.FindAccessToken(tokenURI, "", scopes)
	if err.Error() != "received empty clientID argument" {
		t.Error("error not reported for empty clientID")
	}
	_, err = npStore.FindAccessToken(tokenURI, clientID, []string{})
	if err.Error() != "received empty scopes argument" {
		t.Error("error not reported for empty scopes")
	}

	actual, err := npStore.FindAccessToken(tokenURI, clientID, scopes)
	if err != nil {
		t.Fatal("access token retrieval failed")
	}

	if actual != expected {
		t.Fatalf("incorrect token returned, wanted %s got %s", expected, actual)
	}
}
