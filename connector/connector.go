// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Connector provides LTI Advantage services built upon a successful Launch. The package provides for a "base" Connector
// that can be upgraded to provide either or both Assignment & Grades Services and Names & Roles Provisioning Services.
package connector

import (
	"bytes"
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

// Access Token validity period in seconds. Clock skew allowance in minutes.
const (
	AccessTokenTimeoutSeconds = 3600
	ClockSkewAllowanceMinutes = 2
)

// Timeout value for http clients.
var timeout time.Duration = time.Second * 15

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
	AccessToken datastore.AccessToken
}

// AGS implements Assignment & Grades Services functions.
type AGS struct {
	LineItem  *url.URL
	LineItems *url.URL
	Scopes    []string
	Target    *Connector
}

const (
	// AGS activityProgress constants.
	ActivityInitialized = "Initialized"
	ActivityStarted     = "Started"
	ActivityInProgress  = "InProgress"
	ActvitySubmitted    = "Submitted"
	ActivityCompleted   = "Completed"

	// AGS gradingProgress constants.
	GradingFullyGraded   = "FullyGraded"
	GradingPending       = "Pending"
	GradingPendingManual = "PendingManual"
	GradingFailed        = "Failed"
	GradeNotReady        = "NotReady"
)

// A Score represents a grade assigned by the tool and sent to the platform.
type Score struct {
	Timestamp        string  `json:"timestamp"`
	ScoreGiven       float32 `json:"scoreGiven"`
	ScoreMaximum     float32 `json:"scoreMaximum"`
	Comment          string  `json:"comment"`
	ActivityProgress string  `json:"activityProgress"`
	GradingProgress  string  `json:"gradingProgress"`
	UserID           string  `json:"userId"`
}

// A Result represents a grade assigned by the platform and retrieved by the tool.
type Result struct {
	ID            string
	ScoreOf       string
	UserID        string
	ResultScore   float64
	ResultMaximum float64
	Comment       string
}

// A LineItem represents the specific resource associated with a LTI launch.
// type LineItem struct {
// 	ID             string
// 	StartDateTime  string
// 	EndDateTime    string
// 	ScoreMaximum   float32
// 	Label          string
// 	Tag            string
// 	ResourceID     string
// 	ResourceLinkID string
// }

// NRPS implements Names & Roles Provisioning Services functions.
type NRPS struct {
	Endpoint *url.URL
	Limit    int
	NextPage *url.URL
	Target   *Connector
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

// A Membership represents a course membership with a brief class description.
type Membership struct {
	ID      string
	Context LTIContext
	Members []Member
}

// A LTIContext represents a brief course description used in Names & Roles.
type LTIContext struct {
	ID    string
	Label string
	Title string
}

// A Member represents a participant in a LTI-enabled process.
type Member struct {
	Status             string
	Name               string
	Picture            string
	GivenName          string `json:"given_name"`
	FamilyName         string `json:"family_name"`
	MiddleName         string `json:"middle_name"`
	Email              string
	UserID             string `json:"user_id"`
	LisPersonSourceDid string `json:"lis_person_sourcedid"`
	Roles              []string
}

// New creates a *Connector. To function as expected, a valid launchID must be supplied.
func New(cfg Config, launchID string) (*Connector, error) {
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
		return nil, fmt.Errorf("connector made with empty launch data using launch ID %s", launchID)
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
		return nil, err
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
		return nil, errors.New("names and roles endpoint improperly formatted")
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
		return nil, errors.New("could not parse lineitem URI")
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
		return nil, errors.New("could not parse lineitems URI")
	}

	scope, ok := agsClaims["scope"]
	if !ok {
		return nil, errors.New("could not get AGS scopes")
	}
	scopeInterfaces, ok := scope.([]interface{})
	if !ok {
		return nil, errors.New("could not assert AGS scopes")
	}
	var scopes []string
	for _, v := range scopeInterfaces {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("could not assert an AGS scope")
		}
		scopes = append(scopes, s)
	}

	return &AGS{
		LineItem:  lineItem,
		LineItems: lineItems,
		Scopes:    scopes,
		Target:    c,
	}, nil
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
		return datastore.AccessToken{}, errors.New("suitable access token not found")
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
		return nil, errors.New("failed to sign bearer request token")
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
		return nil, errors.New("could not create http request for get access token")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return request, nil
}

// sendRequest sends the bearer token request to the platform and processes the response.
func sendRequest(req *http.Request) (datastore.AccessToken, error) {
	client := &http.Client{Timeout: timeout}
	response, err := client.Do(req)
	if err != nil {
		return datastore.AccessToken{}, err
	}
	if response.StatusCode != http.StatusOK {
		return datastore.AccessToken{}, fmt.Errorf("access token request got response status %s",
			http.StatusText(response.StatusCode))
	}

	defer response.Body.Close()
	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		return datastore.AccessToken{}, errors.New("could not decode access token reponse body")
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
		return datastore.AccessToken{}, errors.New("could not determine access token expiry time")
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
		return err
	}

	storedToken, err := c.checkAccessTokenStore(registration.AuthTokenURI.String(), registration.ClientID, scopes)
	if err == nil {
		c.AccessToken = storedToken
		return nil
	}

	request, err := c.createRequest(registration.AuthTokenURI.String(), registration.ClientID, scopes)
	if err != nil {
		return err
	}
	responseToken, err := sendRequest(request)
	if err != nil {
		return err
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
		return nil, nil, err
	}

	request, err := http.NewRequest(s.Method, s.URI.String(), s.Body)
	if err != nil {
		return nil, nil, errors.New("could not create http request for service request")
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.AccessToken.Token))
	request.Header.Set("Accept", s.Accept)
	request.Header.Set("Content-Type", s.ContentType)

	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode != s.ExpectedStatus {
		return nil, nil, fmt.Errorf("service request got response status %s", http.StatusText(response.StatusCode))
	}

	return response.Header, response.Body, nil
}

// NRPS Methods.

// GetMembership gets a course (typically referred to as a Context in LTI) membership from the platform.
func (n *NRPS) GetMembership() (Membership, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"}

	_, body, err := n.Target.makeServiceRequest(ServiceRequest{
		Scopes:         scopes,
		Method:         http.MethodGet,
		URI:            n.Endpoint,
		Body:           nil,
		Accept:         "application/vnd.ims.lti-nrps.v2.membershipcontainer+json",
		ExpectedStatus: http.StatusOK,
	})
	if err != nil {
		return Membership{}, err
	}

	defer body.Close()
	var membership Membership
	err = json.NewDecoder(body).Decode(&membership)
	if err != nil {
		return Membership{}, errors.New("could not decode get membership reponse body")
	}

	return membership, nil
}

// GetPageMembership gets paged Memberships from a course, useful for processing large enrollments.
func (n *NRPS) GetPagedMembership(limit int) (Membership, bool, error) {
	if limit < 1 {
		return Membership{}, false, errors.New("must supply a paging limit greater than or equal to one")
	}
	scopes := []string{"https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"}

	query, err := url.ParseQuery(n.Endpoint.RawQuery)
	if err != nil {
		return Membership{}, false, errors.New("could not parse NRPS query values")
	}
	query.Add("limit", strconv.Itoa(limit))

	// Set the initial limit query parameter.
	pagedURI, err := url.Parse(n.Endpoint.String())
	if err != nil {
		return Membership{}, false, errors.New("could not parse NRPS endpoint")
	}
	pagedURI.RawQuery = query.Encode()
	s := ServiceRequest{
		Scopes:         scopes,
		Method:         http.MethodGet,
		URI:            pagedURI,
		Accept:         "application/vnd.ims.lti-nrps.v2.membershipcontainer+json",
		ExpectedStatus: http.StatusOK,
	}

	// If there was a next page set from a previous response, use it.
	if n.NextPage != nil {
		s.URI = n.NextPage
	}
	headers, body, err := n.Target.makeServiceRequest(s)
	if err != nil {
		return Membership{}, false, err
	}

	defer body.Close()
	var membership Membership
	err = json.NewDecoder(body).Decode(&membership)
	if err != nil {
		return Membership{}, false, errors.New("could not decode get membership reponse body")
	}

	// Get the next page link from the response headers.
	nextPageLink := headers.Get("link")
	if nextPageLink == "" || !strings.Contains(nextPageLink, `rel="next"`) {
		// If there are no further next page links, set the NRPS NextPage field to nil.
		n.NextPage = nil
		return membership, false, nil
	} else {
		nextPageString := strings.Trim(nextPageLink, "<>")
		nextPage, err := url.Parse(nextPageString)
		if err != nil {
			return Membership{}, false, errors.New("could not parse next page URI from response headers")
		}
		n.NextPage = nextPage
		return membership, true, nil
	}
}

// GetLaunchingMember returns a Member struct representing the user that performed the launch. Notable omissions
// include Status and Roles, which are not included in the launch message.
func (n *NRPS) GetLaunchingMember() (Member, error) {
	var launchingMember Member

	rawLaunchEmail, ok := n.Target.LaunchToken.Get("email")
	if !ok {
		return Member{}, errors.New("launching member email not found")
	}
	launchEmail, ok := rawLaunchEmail.(string)
	if !ok {
		return Member{}, errors.New("could not assert launching member email")
	}
	launchingMember.Email = launchEmail

	rawFamilyName, ok := n.Target.LaunchToken.Get("family_name")
	if !ok {
		return Member{}, errors.New("launching member family name not found")
	}
	familyName, ok := rawFamilyName.(string)
	if !ok {
		return Member{}, errors.New("could not assert launching member family name")
	}
	launchingMember.FamilyName = familyName

	rawGivenName, ok := n.Target.LaunchToken.Get("given_name")
	if !ok {
		return Member{}, errors.New("launching member family name not found")
	}
	givenName, ok := rawGivenName.(string)
	if !ok {
		return Member{}, errors.New("could not assert launching member family name")
	}
	launchingMember.GivenName = givenName

	rawName, ok := n.Target.LaunchToken.Get("name")
	if !ok {
		return Member{}, errors.New("launching member name not found")
	}
	name, ok := rawName.(string)
	if !ok {
		return Member{}, errors.New("could not assert launching member name")
	}
	launchingMember.Name = name

	launchingMember.UserID = n.Target.LaunchToken.Subject()

	return launchingMember, nil
}

// AGS Methods.

// PutScore posts a grade (LTI spec uses term 'score') for the launched resource to the platform's gradebook.
func (a *AGS) PutScore(s Score) error {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/score"}

	// Make a copy of the lineitem and add the /scores path.
	scoreURI, err := url.Parse(a.LineItem.String())
	if err != nil {
		return errors.New("could not parse score URI")
	}
	scoreURI.Path += "/scores"
	query := a.LineItem.Query()
	scoreURI.RawQuery = query.Encode()

	// The launch data 'sub' claim is the launching user_ID.
	userIDClaim, ok := a.Target.LaunchToken.Get("sub")
	if !ok {
		return errors.New("could not get user ID to publish score")
	}
	userID, ok := userIDClaim.(string)
	if !ok {
		return errors.New("could not assert user ID to publish score")
	}
	s.UserID = userID

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(s)
	if err != nil {
		return errors.New("could not encode body of score publish request")
	}

	_, _, err = a.Target.makeServiceRequest(ServiceRequest{
		Scopes:         scopes,
		Method:         http.MethodPost,
		URI:            scoreURI,
		Body:           &body,
		ContentType:    "application/vnd.ims.lis.v1.score+json",
		ExpectedStatus: http.StatusOK,
	})
	if err != nil {
		return err
	}

	return nil
}

// GetResults fetches the platform-assigned grades for a lineitem.
func (a *AGS) GetResults() ([]Result, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"}

	// Make a copy of the lineitem and add the /scores path.
	resultURI, err := url.Parse(a.LineItem.String())
	if err != nil {
		return []Result{}, errors.New("could not parse score URI")
	}
	resultURI.Path += "/results"
	query := a.LineItem.Query()
	resultURI.RawQuery = query.Encode()

	fmt.Println(resultURI.String())

	_, body, err := a.Target.makeServiceRequest(ServiceRequest{
		Scopes:         scopes,
		Method:         http.MethodGet,
		URI:            resultURI,
		Accept:         "application/vnd.ims.lis.v2.resultcontainer+json",
		ExpectedStatus: http.StatusOK,
	})
	if err != nil {
		return []Result{}, err
	}

	defer body.Close()
	var results []Result
	err = json.NewDecoder(body).Decode(&results)
	if err != nil {
		return []Result{}, errors.New("could not decode get result reponse body")
	}
	// if result.ScoreOf.Path != a.LineItem.Path {
	// 	return Result{}, errors.New("result score of field did not match lineitem")
	// }
	// if result.ResultMaximum <= 0 {
	// 	return Result{}, errors.New("invalid result maximum received")
	// }

	return results, nil
}
