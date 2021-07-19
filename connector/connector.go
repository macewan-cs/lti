// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package connector provides LTI Advantage services built upon a successful Launch. The package provides for a "base"
// Connector that can be upgraded to provide either or both Assignment & Grades Services and Names & Roles Provisioning
// Services.
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

var (
	// ErrUnsupportedService is returned when the connector cannot be upgraded to either NRPS
	// or AGS because the platform does not appear to support the service.
	ErrUnsupportedService = errors.New("platform/LMS does not support the requested service")
)

const (
	// AccessTokenTimeoutSeconds determines the JWT Expiration validity period in seconds.
	AccessTokenTimeoutSeconds = 3600
	// ClockSkewAllowanceMinutes determines the JWT IssuedAt clock skew allowance in minutes.
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
func (c *Connector) setLaunchTokenFromLaunchData(launchID string) error {
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
	registration, err := c.cfg.Registrations.FindRegistrationByIssuerAndClientID(c.LaunchToken.Issuer(), c.LaunchToken.Audience()[0])
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

func convertInterfaceToStringSlice(input []interface{}) []string {
	output := make([]string, len(input))
	for i, v := range input {
		output[i] = fmt.Sprint(v)
	}
	return output
}

// checkAccessTokenStore looks for a suitable, non-expired access token in storage.
func (c *Connector) checkAccessTokenStore(tokenURI, clientID string, scopes []string) (datastore.AccessToken, error) {
	foundToken, err := c.cfg.AccessTokens.FindAccessToken(tokenURI, clientID, scopes)
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
		return datastore.AccessToken{}, fmt.Errorf("could not decode access token response body: %w", err)
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
