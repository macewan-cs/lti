// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package sql

import (
	"database/sql"
	"net/url"
	"reflect"
	"testing"

	"github.com/macewan-cs/lti/datastore"
	_ "github.com/mlhoyt/ramsql/driver"
)

func TestNewConfig(t *testing.T) {
	actualConfig := NewConfig()
	expectedConfig := Config{
		RegistrationTable: "registration",
		RegistrationFields: RegistrationFields{
			Issuer:        "issuer",
			ClientID:      "client_id",
			AuthTokenURI:  "auth_token_uri",
			AuthLoginURI:  "auth_login_uri",
			KeysetURI:     "keyset_uri",
			TargetLinkURI: "target_link_uri",
		},
		DeploymentTable: "deployment",
		DeploymentFields: DeploymentFields{
			Issuer:       "issuer",
			DeploymentID: "deployment_id",
		},
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Errorf("got %#v, wanted %#v", actualConfig, expectedConfig)
	}
}

func TestNew(t *testing.T) {
	db, err := sql.Open("ramsql", "TestNew")
	if err != nil {
		t.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	actualStore := New(db, NewConfig())

	if actualStore.DB != db {
		t.Fatalf("unexpected database: got %v, wanted %v",
			actualStore.DB, db)
	}

	if len(actualStore.registration.table) == 0 ||
		len(actualStore.registration.fields) == 0 ||
		len(actualStore.registration.issuer) == 0 ||
		len(actualStore.deployment.table) == 0 ||
		len(actualStore.deployment.issuer) == 0 ||
		len(actualStore.deployment.deploymentID) == 0 {
		t.Error("one or more fields were unset in the Store")
	}
}

func mustExec(t *testing.T, db *sql.DB, query string) {
	_, err := db.Exec(query)
	if err != nil {
		t.Fatalf("cannot execute query %s: %v", query, err)
	}
}

func mustParse(t *testing.T, rawurl string) *url.URL {
	url, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", rawurl, err)
	}

	return url
}

func newRegistrationForTesting(t *testing.T) datastore.Registration {
	return datastore.Registration{
		Issuer:        "a",
		ClientID:      "b",
		AuthTokenURI:  mustParse(t, "http://c"),
		AuthLoginURI:  mustParse(t, "http://d"),
		KeysetURI:     mustParse(t, "http://e"),
		TargetLinkURI: mustParse(t, "http://f"),
	}
}

func TestStoreRegistration(t *testing.T) {
	db, err := sql.Open("ramsql", "TestStoreRegistration")
	if err != nil {
		t.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	// The UNIQUE constraint (rather than PRIMARY KEY) is necessary for `ramsql'.
	mustExec(t, db, `CREATE TABLE registration (
                           issuer text UNIQUE,
                           client_id text,
                           auth_token_uri text,
                           auth_login_uri text,
                           keyset_uri text,
                           target_link_uri text
                         )`)

	store := New(db, NewConfig())
	registration := newRegistrationForTesting(t)

	err = store.StoreRegistration(registration)
	if err != nil {
		t.Fatalf("cannot store registration: %v", err)
	}

	err = store.StoreRegistration(registration)
	if err == nil {
		t.Fatalf("stored duplicate registration")
	}
}

func TestStoreAndFindRegistrationByIssuer(t *testing.T) {
	db, err := sql.Open("ramsql", "TestFindRegistrationByIssuer")
	if err != nil {
		t.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	// The UNIQUE constraint (rather than PRIMARY KEY) is necessary for `ramsql'.
	mustExec(t, db, `CREATE TABLE registration (
                           issuer text UNIQUE,
                           client_id text,
                           auth_token_uri text,
                           auth_login_uri text,
                           keyset_uri text,
                           target_link_uri text
                         )`)

	store := New(db, NewConfig())
	registration := newRegistrationForTesting(t)

	err = store.StoreRegistration(registration)
	if err != nil {
		t.Fatalf("cannot store registration: %v", err)
	}

	foundRegistration, err := store.FindRegistrationByIssuer("a")
	if err != nil {
		t.Fatalf("cannot find registration: %v", err)
	}

	if !reflect.DeepEqual(registration, foundRegistration) {
		t.Fatalf("got %#v, wanted %#v", foundRegistration, registration)
	}

	foundRegistration, err = store.FindRegistrationByIssuer("b")
	if err == nil {
		t.Fatalf("unexpectedly found registration")
	}
	if err != datastore.ErrRegistrationNotFound {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStoreDeployment(t *testing.T) {
	db, err := sql.Open("ramsql", "TestStoreDeployment")
	if err != nil {
		t.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	// The `ramsql' driver does not handle a unique constraint involving two columns.
	mustExec(t, db, `CREATE TABLE deployment (
                           issuer text,
                           deployment_id text
                         )`)

	store := New(db, NewConfig())

	err = store.StoreDeployment("a", datastore.Deployment{DeploymentID: "b"})
	if err != nil {
		t.Fatalf("cannot store deployment")
	}

	err = store.StoreDeployment("", datastore.Deployment{DeploymentID: "b"})
	if err == nil {
		t.Errorf("issuer not validated")
	}

	err = store.StoreDeployment("a", datastore.Deployment{DeploymentID: "b"})
	if err == nil {
		t.Errorf("deployment ID not validated")
	}
}

func TestFindDeployment(t *testing.T) {
	db, err := sql.Open("ramsql", "TestFindDeployment")
	if err != nil {
		t.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	// The `ramsql' driver does not handle a unique constraint involving two columns.
	mustExec(t, db, `CREATE TABLE deployment (
                           issuer text,
                           deployment_id text
                         )`)

	store := New(db, NewConfig())

	err = store.StoreDeployment("a", datastore.Deployment{DeploymentID: "b"})
	if err != nil {
		t.Fatalf("cannot store deployment")
	}

	deployment, err := store.FindDeployment("a", "b")
	if err != nil {
		t.Fatalf("cannot find deployment: %v", err)
	}
	if deployment.DeploymentID != "b" {
		t.Fatalf("got %#v, wanted %#v", deployment.DeploymentID, "b")
	}

	deployment, err = store.FindDeployment("unknown", "b")
	if err == nil {
		t.Fatalf("unexpectedly found deployment: %#v", deployment)
	}

	deployment, err = store.FindDeployment("a", "unknown")
	if err == nil {
		t.Fatalf("unexpectedly found deployment: %#v", deployment)
	}

	deployment, err = store.FindDeployment("unknown", "unknown")
	if err == nil {
		t.Fatalf("unexpectedly found deployment: %#v", deployment)
	}

	_, err = store.FindDeployment("", "b")
	if err == nil {
		// It should probably be checking for a specific error.
		t.Fatalf("issuer not validated")
	}

	_, err = store.FindDeployment("a", "")
	if err == nil {
		// It should probably be checking for a specific error.
		t.Fatalf("deployment ID not validated")
	}
}
