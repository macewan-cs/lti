// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package datastore implements the interfaces and types for all the different storers used in LTI.
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
// registration. Each Registration is uniquely identified by the ClientID.
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
	// ErrRegistrationNotFound is the error returned when a registration cannot be found.
	ErrRegistrationNotFound = errors.New("registration not found")

	// ErrDeploymentNotFound is the error returned when an issuer/deploymentID cannot be found.
	ErrDeploymentNotFound = errors.New("deployment not found")
)

// A RegistrationStorer manages the storage and retrieval of LTI registrations & deployments.
type RegistrationStorer interface {
	// StoreRegistration stores a registration for later retrieval.
	StoreRegistration(Registration) error

	// FindRegistrationByIssuerAndClientID retrieves a previously-stored registration using the `issuer' and
	// `clientID' fields. If the registration cannot be found, it returns ErrRegistrationNotFound.
	FindRegistrationByIssuerAndClientID(issuer string, clientID string) (Registration, error)

	// StoreDeployment stores a deployment for later retrieval.
	StoreDeployment(issuer string, deployment Deployment) error

	// FindDeployment retrieves a previously-stored deployment using the `issuer' and `deploymentID'. Its primary
	// purpose is to validate the supplied deployment ID. If the deployment cannot be found, it returns
	// ErrDeploymentNotFound.
	FindDeployment(issuer string, deploymentID string) (Deployment, error)
}

var (
	// ErrNonceNotFound is the error returned when a nonce cannot be found.
	ErrNonceNotFound = errors.New("nonce not found")

	// ErrNonceTargetLinkURIMismatch is the error returned when a nonce is found but there's a mismatch in the
	// target URI.
	ErrNonceTargetLinkURIMismatch = errors.New("nonce found with mismatched target link uri")
)

// A NonceStorer manages the storage and retrieval of LTI nonces.
type NonceStorer interface {
	// StoreNonce stores a nonce for later retrieval.
	StoreNonce(nonce string, targetLinkURI string) error

	// TestAndClearNonce tests for the existance of a nonce. If the nonce is found and the target URI matches, it
	// removes/clears the nonce and returns nil. Otherwise, it returns one of the ErrNonce errors.
	TestAndClearNonce(nonce string, targetLinkURI string) error
}

// ErrLaunchDataNotFound is the error returned when cached launch data cannot be found.
var ErrLaunchDataNotFound = errors.New("launch data not found")

// A LaunchDataStorer manages the storage and retrieval of LTI launch data.
type LaunchDataStorer interface {
	// StoreLaunchData stores the JSON launch data associated with the supplied launch ID.
	StoreLaunchData(launchID string, launchData json.RawMessage) error

	// FindLaunchData retrieves previously-stored launch data using the `launchID'. If the launch data cannot be
	// found, it returns ErrLaunchDataNotFound.
	FindLaunchData(launchID string) (json.RawMessage, error)
}

// ErrAccessTokenNotFound is the error returned when an access token cannot be found.
var ErrAccessTokenNotFound = errors.New("access token not found")

// ErrAccessTokenExpired is the error returned when an access token has expired.
var ErrAccessTokenExpired = errors.New("access token has expired")

// An AccessTokenStorer manages the storage and retrieval of access tokens.
type AccessTokenStorer interface {
	// StoreAccessToken stores an access token.
	StoreAccessToken(token AccessToken) error

	// FindAccessToken retrieves a previously-stored access token. If the access token cannot be found, it returns
	// ErrAccessTokenNotFound.
	FindAccessToken(tokenURI, clientID string, scopes []string) (AccessToken, error)
}
