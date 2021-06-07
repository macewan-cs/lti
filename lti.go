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
	"database/sql"
	"net/http"

	"github.com/macewan-cs/lti/connector"
	"github.com/macewan-cs/lti/datastore"
	dssql "github.com/macewan-cs/lti/datastore/sql"
	"github.com/macewan-cs/lti/launch"
	"github.com/macewan-cs/lti/login"
)

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
