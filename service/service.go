// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package service

import (
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

type Config struct {
	LaunchDatas   datastore.LaunchDataStorer
	Registrations datastore.RegistrationStorer
	AccessTokens  datastore.AccessTokenStorer
}

type LTI struct {
	cfg Config
}

type Connector struct {
	LTI      *LTI
	launchID string
	//Store
	//Cookie
	//SigningKeyFunc
	scopes []url.URL
}

type AGS struct {
	LineItem  url.URL
	LineItems []url.URL
	Endpoint  url.URL
	target    Connector
	token     jwt.Token
}

type NRPS struct {
	Endpoint url.URL
	target   Connector
	token    jwt.Token
}

func NewLTI(cfg Config) *LTI {
	lti := LTI{}

	if cfg.LaunchDatas == nil {
		lti.cfg.LaunchDatas = nonpersistent.DefaultStore
	}
	if cfg.AccessTokens == nil {
		lti.cfg.AccessTokens = nonpersistent.DefaultStore
	}
	if cfg.Registrations == nil {
		lti.cfg.Registrations = nonpersistent.DefaultStore
	}

	return &lti
}

func (l *LTI) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}

func (l *LTI) NewConnector(launchID string) *Connector {
	return nil
}

func (c *Connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}

// PlatformKey gets the Platform's public key from the Registration Keyset URL.
func (c *Connector) PlatformKey() (jwk.Set, error) {
	return nil, nil
}

// UpgradeAGS provides a Connector upgraded for AGS calls.
func (c *Connector) UpgradeAGS() (*AGS, error) {
	return nil, nil
}

// UpgradeNRPS provides a Connector upgraded for NRPS calls.
func (c *Connector) UpgradeNRPS() (*NRPS, error) {
	return nil, nil
}

// AccessToken (*AGS receiver) gets AND sets a scoped bearer token for an AGS call.
func (a *AGS) AccessToken(scopes []url.URL) error {
	return nil
}

// AccessToken (*NRPS receiver) gets AND sets a scoped bearer token for an NRPS call.
func (n *NRPS) AccessToken(scopes []url.URL) error {
	return nil
}
