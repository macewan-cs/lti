// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package datastore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Config holds the stores required for LTI packages. New package functions will accept the zero value of this struct,
// and in the case of the zero value, the resulting LTI process will use nonpersistent storage.
type Config struct {
	Registrations RegistrationStorer
	Nonces        NonceStorer
	LaunchData    LaunchDataStorer
	AccessTokens  AccessTokenStorer
}

// A Registration is the details of a link between a Platform and a Tool. There can be multiple deployments per
// registration. Each Registration is uniquely identifed by the ClientID.
type Registration struct {
	Issuer        string
	ClientID      string
	AuthTokenURI  *url.URL
	AuthLoginURI  *url.URL
	KeysetURI     *url.URL
	TargetLinkURI *url.URL
}

// A Deployment contains that details that identify the platform-tool integration for a message.
// Source: http://www.imsglobal.org/spec/lti/v1p3/#lti-deployment-id-claim.
type Deployment struct {
	DeploymentID string
}

// An AccessToken is the scoped bearer token used for direct communication between the platform and tool.
type AccessToken struct {
	TokenURI   string    `json:"tokenURI"`
	ClientID   string    `json:"clientID"`
	Scopes     []string  `json:"scopes"`
	Token      string    `json:"token"`
	ExpiryTime time.Time `json:"expiryTime"`
}

var maximumDeploymentIDLength = 255

// ValidateDeploymentID validates a deployment ID.
func ValidateDeploymentID(deploymentID string) error {
	if len(deploymentID) == 0 {
		return errors.New("empty deployment ID")
	}
	if len(deploymentID) > maximumDeploymentIDLength {
		return fmt.Errorf("exceeds maximum length (%d)", maximumDeploymentIDLength)
	}

	return nil
}

var (
	ErrRegistrationNotFound = errors.New("registration not found")
	ErrDeploymentNotFound   = errors.New("deployment not found")
)

type RegistrationStorer interface {
	StoreRegistration(Registration) error
	StoreDeployment(issuer string, deploymentID string) error
	FindRegistrationByIssuer(issuer string) (Registration, error)
	FindDeployment(issuer string, deploymentID string) (Deployment, error)
}

var (
	ErrNonceNotFound              = errors.New("nonce not found")
	ErrNonceTargetLinkURIMismatch = errors.New("nonce found with mismatched target link uri")
)

type NonceStorer interface {
	StoreNonce(nonce string, targetLinkURI string) error
	TestAndClearNonce(nonce string, issuer string) error
}

var ErrLaunchDataNotFound = errors.New("launch data not found")

type LaunchDataStorer interface {
	StoreLaunchData(launchID string, launchData json.RawMessage) error
	FindLaunchData(launchID string) (json.RawMessage, error)
}

var ErrAccessTokenNotFound = errors.New("access token not found")

type AccessTokenStorer interface {
	StoreAccessToken(token AccessToken) error
	FindAccessToken(token AccessToken) (AccessToken, error)
}
