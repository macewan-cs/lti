// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Connector provides LTI Advantage services built upon a successful Launch. The package provides for a "base" Connector
// that can be upgraded to provide either or both Assignment & Grades Services and Names & Roles Provisioning Services.
package connector

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

// Access Token validity period in minutes. Clock skew allowance in minutes.
const (
	AccessTokenTimeoutMinutes = 60
	ClockSkewAllowance        = 2
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
	SigningKey  *rsa.PrivateKey
	AccessToken string
	//SigningKeyFunc func([]byte) (*rsa.PrivateKey, error)
}

// AGS implements Assignment & Grades Services functions.
type AGS struct {
	LineItem  url.URL
	LineItems []url.URL
	Endpoint  url.URL
	Target    Connector
	Scopes    []url.URL
}

// NRPS implements Names & Roles Provisioning Services functions.
type NRPS struct {
	Endpoint url.URL
	Target   Connector
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
	if connector.cfg.Registrations == nil {
		connector.cfg.Registrations = nonpersistent.DefaultStore
	}
	if connector.cfg.AccessTokens == nil {
		connector.cfg.AccessTokens = nonpersistent.DefaultStore
	}

	// New could perhaps return (*Connector, error).
	err := connector.setLaunchTokenFromLaunchData(launchID)
	if err != nil {
		log.Printf("connector made with empty launch data using launch ID %s", launchID)
	}

	return &connector
}

// SetSigningKey takes a PEM encoded private key and sets the signing key to the corresponding RSA private key.
func (c *Connector) SetSigningKey(pemPrivateKey string) error {
	if len(pemPrivateKey) == 0 {
		return errors.New("received empty signing key")
	}

	pemPrivateKeyBytes := []byte(pemPrivateKey)
	pemBlock, _ := pem.Decode(pemPrivateKeyBytes)
	if pemBlock == nil {
		return errors.New("failed to decode PEM key block")
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return errors.New("failed to parse RSA key")
	}

	c.SigningKey = rsaPrivateKey

	return nil
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

// checkAccessTokenStore looks for a suitable, non-expired access token in storage.
// func (c *Connector) checkAccessTokenStore(tokenURI, clientID string, scopes []string) string {
// 	token, err := c.cfg.AccessTokens.FindAccessToken(tokenURI, clientID, scopes)
// 	if err != nil {
// 		return nil
// 	}

// 	accessToken, err := jwt.ParseString(token)
// 	if err != nil {
// 		return nil
// 	}
// 	if accessToken.Expiration().Before(time.Now()) {
// 		return nil
// 	}

// 	return accessToken.Token
// }

// GetAccessToken gets a scoped bearer token for use by a connector.
func (c *Connector) GetAccessToken(scopes []string) error {
	registration, err := c.getRegistration()
	if err != nil {
		return err
	}
	sort.Strings(scopes)

	// storedToken := c.checkAccessTokenStore(registration.AuthTokenURI.String(), registration.ClientID, scopes)
	// if storedToken != nil {
	// 	c.AccessToken = storedToken
	// 	return nil
	// }

	token := jwt.New()
	token.Set(jwt.IssuerKey, registration.ClientID)
	token.Set(jwt.SubjectKey, registration.ClientID)
	token.Set(jwt.AudienceKey, registration.AuthTokenURI.String())
	token.Set(jwt.IssuedAtKey, time.Now().Add(-time.Minute*ClockSkewAllowance))
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*AccessTokenTimeoutMinutes))
	token.Set(jwt.JwtIDKey, "lti-service-token"+uuid.New().String())

	key := c.SigningKey
	if key == nil {
		return errors.New("signing key has not been set")
	}
	signedToken, err := jwt.Sign(token, jwa.RS256, key)
	if err != nil {
		fmt.Println(err)
	}

	var scopeValue string
	for _, val := range scopes {
		scopeValue += " " + val
	}
	// Testing value for scope:
	scopeValue = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"

	requestValues := url.Values{}
	requestValues.Add("grant_type", "client_credentials")
	requestValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	requestValues.Add("client_assertion", string(signedToken))
	requestValues.Add("scope", scopeValue)

	requestBody := strings.NewReader(requestValues.Encode())
	request, err := http.NewRequest("POST", registration.AuthTokenURI.String(), requestBody)
	if err != nil {
		fmt.Println(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println(err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("access token request got response status: %s", http.StatusText(response.StatusCode))
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.New("could not read access token response body")
	}
	var responseBody map[string]interface{}
	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		return errors.New("could not decode access token reponse body")
	}

	for k, v := range responseBody {
		fmt.Printf("key %s, val %v\n", k, v)
	}

	responseToken, ok := responseBody["access_token"].(string)
	if !ok {
		return errors.New("could not format access token from response")
	}
	fmt.Println("key lookup 'access_token' gave: " + responseToken)

	c.AccessToken = responseToken

	return nil
}
