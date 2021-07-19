// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package lti supports the development of LTI 1.3 tools. It provides types and methods to support the OpenID Connect
// flow, the tool launch, and the use of a platform's 'Names and Role Provisioning Services' and 'Assignment and Grade
// Services.'
package lti

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/macewan-cs/lti/connector"
	"github.com/macewan-cs/lti/datastore"
	dssql "github.com/macewan-cs/lti/datastore/sql"
	"github.com/macewan-cs/lti/launch"
	"github.com/macewan-cs/lti/login"
)

// JSONWebKeySet provides configuration for a keyset handler implemented on this type. The ServeHTTP method is
// implemented for this type to allow it to serve as an http.Handler.
type JSONWebKeySet struct {
	Identifier string
	PrivateKey string
}

// KeySet is encoded to provide the public key to be fetched in order to verify the authenticity of JSON Web Tokens
// sent from this library.
type KeySet struct {
	Keys [1]jwk.Key `json:"keys"`
}

// NewSQLDatastoreConfig returns a new SQL datastore configuration containing the library's default table and field
// names. These table and field names can be modified before calling NewSQLDatastore.
func NewSQLDatastoreConfig() dssql.Config {
	return dssql.NewConfig()
}

// NewSQLDatastore returns a new SQL datastore using the provided configuration. The configuration provides the table
// and field names used in queries on that database.
func NewSQLDatastore(db *sql.DB, config dssql.Config) *dssql.Store {
	return dssql.New(db, config)
}

// NewDatastoreConfig returns a new datastore configuration. Unless specified otherwise, all of the data stores will be
// internal/nonpersistent.
func NewDatastoreConfig() datastore.Config {
	return datastore.Config{}
}

// NewLogin returns a pointer to a new Login object. This object is an http.Handler so it can easily be associated with
// tool URI, e.g., /services/lti/login/. It also provides other methods related to the redirect back to the platform.
func NewLogin(cfg datastore.Config) *login.Login {
	return login.New(cfg)
}

// NewLaunch returns a pointer to a new Launch object. This object is an http.Handler so it can be easily associated
// with a tool URI, e.g., /services/lti/launch/. Its second argument, `next', is the HTTP handler to run on a successful
// launch.
//
// After a successful launch, further LTI requests must include the launch ID in their requests. To support a variety of
// tool implementation, the launch ID is attached to the *http.Request context immediately prior to calling
// `next'. Convenience functions, like `LaunchIDFromRequest' and `LaunchIDFromContext', also available in this package,
// simplify the retrieval of this launch ID.
func NewLaunch(cfg datastore.Config, next http.HandlerFunc) *launch.Launch {
	return launch.New(cfg, next)
}

// GetLaunchContextKey returns the context key used for attaching the launch ID to the request context.
func GetLaunchContextKey() launch.ContextKeyType {
	return launch.ContextKey
}

// LaunchIDFromContext takes the context of an *http.Request (after a successful launch), and it returns the launch ID
// that was attached to that context.
func LaunchIDFromContext(ctx context.Context) string {
	launchID := ctx.Value(GetLaunchContextKey())
	if launchID == nil {
		return ""
	}

	return launchID.(string)
}

// LaunchIDFromRequest takes an *http.Request (after a successful launch), and it returns the launch ID that was
// attached to that request.
func LaunchIDFromRequest(r *http.Request) string {
	return LaunchIDFromContext(r.Context())
}

// NewConnector returns a *connector.Connector (on success) that can be used for accessing LTI services. These services
// include Names and Role Provisioning Services (NRPS) and Assignments and Grade Services (AGS). The returned connector
// needs to be successfully `upgraded' (which returns a new type) before it can be used for these services.
func NewConnector(cfg datastore.Config, launchID string) (*connector.Connector, error) {
	return connector.New(cfg, launchID)
}

// NewKeySet returns a *JSONWebKeySet that provides the key used to verify the sender authenticity of JSON Web Tokens
// exchanged as part of accessing LTI services between Platforms and Tools. This object is an http.handler so it can be
// easily associated with a keyset URI, e.g., /services/lti/keyset.
func NewKeySet(identifier, privateKey string) *JSONWebKeySet {
	jsonWebKeySet := JSONWebKeySet{
		Identifier: identifier,
		PrivateKey: privateKey,
	}

	return &jsonWebKeySet
}

// ServeHTTP makes the JSONWebKeySet type a handler to provide a JSON Web Key Set response for key fetch requests.
func (j *JSONWebKeySet) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	block, _ := pem.Decode([]byte(j.PrivateKey))
	if block == nil {
		http.Error(w, "failed to parse key", http.StatusInternalServerError)
		return

	}
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	key, err := jwk.New(&privkey.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key.Set(jwk.KeyIDKey, j.Identifier)
	key.Set(jwk.AlgorithmKey, "RS256")
	key.Set(jwk.KeyUsageKey, "sig")

	var keyArr [1]jwk.Key = [1]jwk.Key{key}
	jwks := KeySet{
		Keys: keyArr,
	}

	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.Encode(jwks)
}
