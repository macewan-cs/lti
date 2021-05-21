// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package lti supports the development of LTI 1.3 tools. It provides
// types and methods to support the OpenID Connect flow, the tool
// launch, and the use of a platform's ``Names and Role Provisioning
// Services'' and ``Assignment and Grade Services.''
package lti

import (
	"context"
	"net/http"

	"github.com/macewan-cs/lti/connector"
	"github.com/macewan-cs/lti/launch"
	"github.com/macewan-cs/lti/login"
)

func NewLoginConfig() login.Config {
	return login.Config{}
}

func NewLogin(cfg login.Config) *login.Login {
	return login.New(cfg)
}

func NewLaunchConfig() launch.Config {
	return launch.Config{}
}

func NewLaunch(cfg launch.Config, next http.HandlerFunc) *launch.Launch {
	return launch.New(cfg, next)
}

func GetLaunchContextKey() launch.LaunchContextKeyType {
	return launch.LaunchContextKey
}

func LaunchIDFromContext(ctx context.Context) string {
	launchID := ctx.Value(GetLaunchContextKey())
	if launchID == nil {
		return ""
	}

	return launchID.(string)
}

func LaunchIDFromRequest(r *http.Request) string {
	return LaunchIDFromContext(r.Context())
}

func NewConnectorConfig() connector.Config {
	return connector.Config{}
}

func NewConnector(cfg connector.Config, launchID string) *connector.Connector {
	return connector.New(cfg, launchID)
}