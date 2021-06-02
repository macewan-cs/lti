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
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/macewan-cs/lti/datastore"
	"github.com/macewan-cs/lti/datastore/nonpersistent"
)

const (
	// Access Token request JWT Expiration validity period in seconds.
	AccessTokenTimeoutSeconds = 3600
	// Access Token request JWT IssuedAt clock skew allowance in minutes.
	ClockSkewAllowanceMinutes = 2
)

// Timeout value for http clients.
var timeout time.Duration = time.Second * 15

// A Connector implements the base that underpins LTI 1.3 Advantage, i.e. AGS or NRPS.
type Connector struct {
	cfg         datastore.Config
	LaunchID    string
	LaunchToken jwt.Token
	SigningKey  *rsa.PrivateKey
	AccessToken datastore.AccessToken
}

// A ServiceRequest structures service (AGS & NRPS) connections between tool and platform.
type ServiceRequest struct {
	Scopes         []string
	Method         string
	URI            *url.URL
	Body           io.Reader
	ContentType    string
	Accept         string
	ExpectedStatus int
}

// New creates a *Connector. To function as expected, a valid launchID must be supplied.
func New(cfg datastore.Config, launchID string) (*Connector, error) {
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

	err := connector.setLaunchTokenFromLaunchData(launchID)
	if err != nil {
		return nil, fmt.Errorf("connector made with empty launch data using launch ID %s: %w", launchID, err)
	}

	return &connector, nil
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
		return fmt.Errorf("failed to parse RSA key: %w", err)
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
		return fmt.Errorf("error decoding launch data: %w", err)
	}
	idTokenPayload, err := jwt.Parse(launchData)
	if err != nil {
		return fmt.Errorf("error encoding launch data token: %w", err)
	}

	c.LaunchToken = idTokenPayload

	return nil
}

// getRegistration uses the Connector's LaunchToken issuer to get the associated registration.
func (c *Connector) getRegistration() (datastore.Registration, error) {
	registration, err := c.cfg.Registrations.FindRegistrationByIssuer(c.LaunchToken.Issuer())
	if err != nil {
		return datastore.Registration{}, err
	}

	return registration, nil
}

// PlatformKey gets the Platform's public key from the Registration Keyset URI.
func (c *Connector) PlatformKey() (jwk.Set, error) {
	registration, err := c.getRegistration()
	if err != nil {
		return nil, err
	}

	keyset, err := jwk.Fetch(context.Background(), registration.KeysetURI.String())
	if err != nil {
		return nil, fmt.Errorf("error fetching keyset: %w", err)
	}

	return keyset, nil
}

// UpgradeNRPS provides a Connector upgraded for NRPS calls.
func (c *Connector) UpgradeNRPS() (*NRPS, error) {
	// Check for endpoint.
	nrpsRawClaim, ok := c.LaunchToken.Get("https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice")
	if !ok {
		return nil, errors.New("names and roles endpoint not found in launch data")
	}
	nrpsClaim, ok := nrpsRawClaim.(map[string]interface{})
	if !ok {
		return nil, errors.New("names and roles information improperly formatted")
	}
	nrpsString, ok := nrpsClaim["context_memberships_url"]
	if !ok {
		return nil, errors.New("names and roles endpoint not found")
	}
	nrps, err := url.Parse(nrpsString.(string))
	if err != nil {
		return nil, fmt.Errorf("names and roles endpoint parse error: %w", err)
	}

	return &NRPS{
		Endpoint: nrps,
		Target:   c,
	}, nil
}

// UpgradeAGS provides a Connector upgraded for AGS calls.
func (c *Connector) UpgradeAGS() (*AGS, error) {
	// Check for endpoint.
	agsRawClaims, ok := c.LaunchToken.Get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint")
	if !ok {
		return nil, errors.New("assignments and grades endpoint not found in launch data")
	}
	agsClaims, ok := agsRawClaims.(map[string]interface{})
	if !ok {
		return nil, errors.New("assignments and grades information improperly formatted")
	}

	rawLineItem, ok := agsClaims["lineitem"]
	if !ok {
		return nil, errors.New("could not get lineitem URI")
	}
	lineItemString, ok := rawLineItem.(string)
	if !ok {
		return nil, errors.New("could not assert lineitem URI")
	}
	lineItem, err := url.Parse(lineItemString)
	if err != nil {
		return nil, fmt.Errorf("could not parse lineitem URI: %w", err)
	}

	rawLineItems, ok := agsClaims["lineitems"]
	if !ok {
		return nil, errors.New("could not get lineitems URI")
	}
	lineItemsString, ok := rawLineItems.(string)
	if !ok {
		return nil, errors.New("could not assert lineitems URI")
	}
	lineItems, err := url.Parse(lineItemsString)
	if err != nil {
		return nil, fmt.Errorf("could not parse lineitems URI: %w", err)
	}

	scope, ok := agsClaims["scope"]
	if !ok {
		return nil, errors.New("could not get AGS scopes")
	}
	scopeInterfaces, ok := scope.([]interface{})
	if !ok {
		return nil, errors.New("could not assert AGS scopes")
	}
	scopes := convertInterfaceToStringSlice(scopeInterfaces)

	return &AGS{
		LineItem:  lineItem,
		LineItems: lineItems,
		Scopes:    scopes,
		Target:    c,
	}, nil
}

func convertInterfaceToStringSlice(input []interface{}) []string {
	output := make([]string, len(input))
	for i, v := range input {
		output[i] = fmt.Sprint(v)
	}
	return output
}

// checkAccessTokenStore looks for a suitable, non-expired access token in storage.
func (c *Connector) checkAccessTokenStore(tokenURI, clientID string, scopes []string) (datastore.AccessToken, error) {
	searchToken := datastore.AccessToken{
		TokenURI: tokenURI,
		ClientID: clientID,
		Scopes:   scopes,
	}

	foundToken, err := c.cfg.AccessTokens.FindAccessToken(searchToken)
	if err != nil {
		return datastore.AccessToken{}, fmt.Errorf("suitable access token not found: %w", err)
	}
	if foundToken.ExpiryTime.Before(time.Now()) {
		return datastore.AccessToken{}, errors.New("access token found but has expired")
	}

	return foundToken, nil
}

// createRequest creates a signed bearer request JWT as part of an *http.Request to be sent to the platform.
func (c *Connector) createRequest(tokenURI, clientID string, scopes []string) (*http.Request, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, clientID)
	token.Set(jwt.SubjectKey, clientID)
	token.Set(jwt.AudienceKey, tokenURI)
	token.Set(jwt.IssuedAtKey, time.Now().Add(-time.Minute*ClockSkewAllowanceMinutes))
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Second*AccessTokenTimeoutSeconds))
	token.Set(jwt.JwtIDKey, "lti-service-token"+uuid.New().String())

	key := c.SigningKey
	if key == nil {
		return nil, errors.New("signing key has not been set for this connector")
	}
	signedToken, err := jwt.Sign(token, jwa.RS256, key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign bearer request token: %w", err)
	}

	var scopeValue string
	for _, val := range scopes {
		scopeValue += val + " "
	}

	requestValues := url.Values{}
	requestValues.Add("grant_type", "client_credentials")
	requestValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	requestValues.Add("client_assertion", string(signedToken))
	requestValues.Add("scope", scopeValue)
	requestBody := strings.NewReader(requestValues.Encode())
	request, err := http.NewRequest(http.MethodPost, tokenURI, requestBody)
	if err != nil {
		return nil, fmt.Errorf("could not create http request for get access token: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return request, nil
}

// sendRequest sends the bearer token request to the platform and processes the response.
func sendRequest(req *http.Request) (datastore.AccessToken, error) {
	client := &http.Client{Timeout: timeout}
	response, err := client.Do(req)
	if err != nil {
		return datastore.AccessToken{}, fmt.Errorf("send request error: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return datastore.AccessToken{}, fmt.Errorf("access token request got response status %s",
			http.StatusText(response.StatusCode))
	}

	defer response.Body.Close()
	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		return datastore.AccessToken{}, fmt.Errorf("could not decode access token reponse body: %w", err)
	}

	responseToken, ok := responseBody["access_token"].(string)
	if !ok {
		return datastore.AccessToken{}, errors.New("could not format access token from response")
	}
	expiresIn, ok := responseBody["expires_in"].(float64)
	if !ok {
		return datastore.AccessToken{}, errors.New("could not format access token expiry time")
	}
	expiry, err := time.ParseDuration(strconv.FormatFloat(expiresIn, 'f', -1, 64) + "s")
	if err != nil {
		return datastore.AccessToken{}, fmt.Errorf("could not determine access token expiry time: %w", err)
	}

	return datastore.AccessToken{
		TokenURI:   req.URL.String(),
		Token:      responseToken,
		ExpiryTime: time.Now().Add(expiry),
	}, nil
}

// GetAccessToken gets a scoped bearer token for use by a connector.
func (c *Connector) GetAccessToken(scopes []string) error {
	registration, err := c.getRegistration()
	if err != nil {
		return fmt.Errorf("get registration for access token: %w", err)
	}

	storedToken, err := c.checkAccessTokenStore(registration.AuthTokenURI.String(), registration.ClientID, scopes)
	if err == nil {
		c.AccessToken = storedToken
		return nil
	}

	request, err := c.createRequest(registration.AuthTokenURI.String(), registration.ClientID, scopes)
	if err != nil {
		return fmt.Errorf("create request for access token: %w", err)
	}
	responseToken, err := sendRequest(request)
	if err != nil {
		return fmt.Errorf("send request for access token: %w", err)
	}
	responseToken.ClientID = registration.ClientID
	responseToken.Scopes = scopes

	c.cfg.AccessTokens.StoreAccessToken(responseToken)
	c.AccessToken = responseToken

	return nil
}

// makeServiceRequest makes direct tool to platform requests.
func (c *Connector) makeServiceRequest(s ServiceRequest) (http.Header, io.ReadCloser, error) {
	if len(s.Scopes) == 0 {
		return nil, nil, errors.New("empty scope for service request")
	}
	method := strings.ToUpper(s.Method)
	if (method == http.MethodPost || method == http.MethodPut) && s.ContentType == "" {
		s.ContentType = "application/json"
	}
	if s.Accept == "" {
		s.Accept = "application/json"
	}
	if s.ExpectedStatus == 0 {
		s.ExpectedStatus = http.StatusOK
	}

	err := c.GetAccessToken(s.Scopes)
	if err != nil {
		return nil, nil, fmt.Errorf("get access token for service request: %w", err)
	}

	request, err := http.NewRequest(s.Method, s.URI.String(), s.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create http request for service request: %w", err)
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.AccessToken.Token))
	request.Header.Set("Accept", s.Accept)
	request.Header.Set("Content-Type", s.ContentType)

	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("make service request client error: %w", err)
	}
	if response.StatusCode != s.ExpectedStatus {
		return nil, nil, fmt.Errorf("service request got response status %s", http.StatusText(response.StatusCode))
	}

	return response.Header, response.Body, nil
}
