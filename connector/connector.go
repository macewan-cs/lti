// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Connector provides LTI Advantage services built upon a successful Launch. The package provides for a "base" Connector
// that can be upgraded to provide either or both Assignment & Grades Services and Names & Roles Provisioning Services.
package connector

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

// Config represents the configuration used in creating a new *Connector. New will accept the zero value of this struct,
// and in the case of the zero value, the resulting Connector will use nonpersistent storage.
type Config struct {
	LaunchData    datastore.LaunchDataStorer
	Registrations datastore.RegistrationStorer
	AccessTokens  datastore.AccessTokenStorer
}

// A Connector implements the base that underpins LTI 1.3 Advantage, i.e. AGS or NRPS.
type Connector struct {
	cfg         Config
	LaunchID    string
	LaunchToken jwt.Token
	//SigningKeyFunc
	//Scopes []url.URL
}

// AGS implements Assignment & Grades Services functions.
type AGS struct {
	LineItem  url.URL
	LineItems []url.URL
	Endpoint  url.URL
	Target    Connector
	Scopes    []url.URL
	//token     jwt.Token
}

// NRPS implements Names & Roles Provisioning Services functions.
type NRPS struct {
	Endpoint url.URL
	Target   Connector
	//token    jwt.Token
}

// New creates a *Connector. To function as expected, a valid launchID must be supplied.
func New(cfg Config, launchID string) *Connector {
	connector := Connector{
		cfg:      cfg,
		LaunchID: launchID,
	}

	if connector.cfg.LaunchData == nil {
		connector.cfg.LaunchData = nonpersistent.DefaultStore
	}
	if connector.cfg.AccessTokens == nil {
		connector.cfg.AccessTokens = nonpersistent.DefaultStore
	}
	if connector.cfg.Registrations == nil {
		connector.cfg.Registrations = nonpersistent.DefaultStore
	}

	// New could perhaps return (*Connector, error).
	err := connector.setLaunchTokenFromLaunchData(launchID)
	if err != nil {
		log.Printf("connector made with blank token using launch ID %s", launchID)
	}

	return &connector
}

// setTokenFromLaunchData populates the Connector's token with stored launch data that is derived from the OIDC id_token
// payload. That id_token had its authenticity previously verified as part of the launch process.
func (c *Connector) setLaunchTokenFromLaunchData(launchId string) error {
	if c.LaunchID == "" {
		return errors.New("received empty launch ID")
	}

	rawLaunchData, err := c.cfg.LaunchData.FindLaunchData(c.LaunchID)
	if err != nil {
		return err
	}
	launchData, err := rawLaunchData.MarshalJSON()
	if err != nil {
		return errors.New("error decoding launch data")
	}
	idTokenPayload, err := jwt.Parse(launchData)
	if err != nil {
		return errors.New("error encoding launch data token")
	}

	c.LaunchToken = idTokenPayload

	return nil
}

// getRegistration uses the Connector's LaunchToken issuer to get that associated registeration.
func (c *Connector) getRegistration() (datastore.Registration, error) {
	registration, err := c.cfg.Registrations.FindRegistrationByIssuer(c.LaunchToken.Issuer())
	if err != nil {
		return datastore.Registration{}, err
	}

	return registration, nil
}

// PlatformKey gets the Platform's public key from the Registration Keyset URL.
func (c *Connector) PlatformKey() (jwk.Set, error) {
	registration, err := c.getRegistration()
	if err != nil {
		return nil, err
	}

	keyset, err := jwk.Fetch(context.Background(), registration.KeysetURI.String())
	if err != nil {
		return nil, err
	}

	return keyset, nil
}

// UpgradeNRPS provides a Connector upgraded for NRPS calls.
func (c *Connector) UpgradeNRPS() (*NRPS, error) {
	// Check for endpoint.
	nrpsClaim, ok := c.LaunchToken.Get("https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice")
	if !ok {
		return nil, errors.New("names and roles endpoint not found in launch data")
	}
	nrpsMap, ok := nrpsClaim.(map[string]interface{})
	if !ok {
		return nil, errors.New("names and roles information improperly formatted")
	}
	nrpsVal, ok := nrpsMap["context_memberships_url"]
	if !ok {
		return nil, errors.New("names and roles endpoint not found")
	}
	nrpsURI, err := url.Parse(nrpsVal.(string))
	if err != nil {
		return nil, errors.New("names and roles endpoint improperly formatted")
	}

	return &NRPS{Endpoint: *nrpsURI, Target: *c}, nil
}

// UpgradeAGS provides a Connector upgraded for AGS calls.
func (c *Connector) UpgradeAGS() (*AGS, error) {
	// Check for endpoint.
	agsClaim, ok := c.LaunchToken.Get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint")
	if !ok {
		return nil, errors.New("assignments and grades endpoint not found in launch data")
	}
	agsMap, ok := agsClaim.(map[string]interface{})
	if !ok {
		return nil, errors.New("assignments and grades information improperly formatted")
	}

	for key, val := range agsMap {
		fmt.Println(key, val)
	}

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
