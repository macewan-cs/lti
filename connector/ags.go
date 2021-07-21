// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// AGS implements Assignment & Grades Services functions.
type AGS struct {
	LineItem  *url.URL
	LineItems *url.URL
	Scopes    []string
	NextPage  *url.URL
	Target    *Connector
}

// AGS activityProgress constants.
const (
	ActivityInitialized = "Initialized"
	ActivityStarted     = "Started"
	ActivityInProgress  = "InProgress"
	ActivitySubmitted   = "Submitted"
	ActivityCompleted   = "Completed"
)

// AGS gradingProgress constants.
const (
	GradingFullyGraded   = "FullyGraded"
	GradingPending       = "Pending"
	GradingPendingManual = "PendingManual"
	GradingFailed        = "Failed"
	GradeNotReady        = "NotReady"
)

// A Score represents a grade assigned by the tool and sent to the platform.
type Score struct {
	Timestamp        string  `json:"timestamp"`
	ScoreGiven       float64 `json:"scoreGiven"`
	ScoreMaximum     float64 `json:"scoreMaximum"`
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
type LineItem struct {
	ID             string  `json:"id,omitempty"`
	StartDateTime  string  `json:"startDateTime,omitempty"`
	EndDateTime    string  `json:"endDateTime,omitempty"`
	ScoreMaximum   float64 `json:"scoreMaximum,omitempty"`
	Label          string  `json:"label,omitempty"`
	Tag            string  `json:"tag,omitempty"`
	ResourceID     string  `json:"resourceId,omitempty"`
	ResourceLinkID string  `json:"resourceLinkId,omitempty"`
}

// UpgradeAGS provides a Connector upgraded for AGS calls.
func (c *Connector) UpgradeAGS() (*AGS, error) {
	// Check for endpoint.
	agsRawClaims, ok := c.LaunchToken.Get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint")
	if !ok {
		return nil, ErrUnsupportedService
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

// PutScore posts a grade (LTI spec uses term 'score') for the launched resource to the platform's gradebook. The
// useLaunchUserID argument specifies if the launching user's ID is used; supply false to send the user ID embedded in
// the score argument.
func (a *AGS) PutScore(s Score, useLaunchUserID bool) error {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/score"}

	// Make a copy of the lineitem and add the /scores path.
	scoreURI, err := url.Parse(a.LineItem.String())
	if err != nil {
		return fmt.Errorf("could not parse score URI: %w", err)
	}
	scoreURI.Path += "/scores"
	query := a.LineItem.Query()
	scoreURI.RawQuery = query.Encode()

	if useLaunchUserID {
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
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(s)
	if err != nil {
		return fmt.Errorf("could not encode body of score publish request: %w", err)
	}

	_, _, err = a.Target.makeServiceRequest(ServiceRequest{
		Scopes:      scopes,
		Method:      http.MethodPost,
		URI:         scoreURI,
		Body:        &body,
		ContentType: "application/vnd.ims.lis.v1.score+json",
	})
	if err != nil {
		return fmt.Errorf("put score make service request error: %w", err)
	}

	return nil
}

// GetResults gets the launched limeitem's Results for all users enrolled in that lineitem's context (i.e. course).
func (a *AGS) GetResults() ([]Result, error) {
	return a.resultsGetter("")
}

// GetUserResults is the same as GetResults with the addition of a user ID to filter the Results service responses.
func (a *AGS) GetUserResults(userID string) ([]Result, error) {
	if userID == "" {
		return []Result{}, errors.New("received empty userID")
	}
	return a.resultsGetter(userID)
}

// resultsGetter gets Results service responses, using GetPagedMemberships as a helper.
func (a *AGS) resultsGetter(userID string) ([]Result, error) {
	var (
		limit       int
		hasMore     bool
		results     []Result
		moreResults []Result
		err         error
	)

	results, hasMore, err = a.GetPagedResults(limit, userID)
	if err != nil {
		return []Result{}, fmt.Errorf("get paged membership error: %w", err)
	}

	for hasMore {
		moreResults, hasMore, err = a.GetPagedResults(limit, userID)
		if err != nil {
			return []Result{}, fmt.Errorf("get more membership error: %w", err)
		}
		results = append(results, moreResults...)
	}

	return results, nil
}

// GetPagedResults fetches the platform-assigned grades for a lineitem. Note: Platforms are not required to support a
// Results service 'limit' parameter, see: https://www.imsglobal.org/spec/lti-ags/v2p0/#container-request-filters-0
// It checks for next page links, fetching and appending them to the output.
func (a *AGS) GetPagedResults(limit int, userID string) ([]Result, bool, error) {
	if limit < 0 {
		return []Result{}, false, errors.New("invalid paging limit")
	}
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"}

	query, err := url.ParseQuery(a.LineItem.RawQuery)
	if err != nil {
		return []Result{}, false, fmt.Errorf("could not parse lineitem query values: %w", err)
	}
	if limit != 0 {
		query.Add("limit", strconv.Itoa(limit))
	}
	if userID != "" {
		query.Add("user_id", userID)
	}

	// Make a copy of the lineitem and add the /results path.
	resultURI, err := url.Parse(a.LineItem.String())
	if err != nil {
		return []Result{}, false, fmt.Errorf("could not parse score URI: %w", err)
	}
	resultURI.Path += "/results"
	resultURI.RawQuery = query.Encode()
	s := ServiceRequest{
		Scopes: scopes,
		Method: http.MethodGet,
		URI:    resultURI,
		Accept: "application/vnd.ims.lis.v2.resultcontainer+json",
	}

	// If there was a next page set from a previous response, use it.
	if a.NextPage != nil {
		s.URI = a.NextPage
	}
	headers, body, err := a.Target.makeServiceRequest(s)
	if err != nil {
		return []Result{}, false, fmt.Errorf("get results make service request error: %w", err)
	}

	defer body.Close()
	var results []Result
	err = json.NewDecoder(body).Decode(&results)
	if err != nil {
		return []Result{}, false, fmt.Errorf("could not decode get result response body: %w", err)
	}

	// Get the next page link from the response headers.
	nextPageLink := headers.Get("link")
	if nextPageLink == "" || !strings.Contains(nextPageLink, `rel="next"`) {
		// If there are no further next page links, set the AGS NextPage field to nil.
		a.NextPage = nil
		return results, false, nil
	}

	nextPageString := strings.Trim(nextPageLink, "<>")
	nextPage, err := url.Parse(nextPageString)
	if err != nil {
		return []Result{}, false, fmt.Errorf("could not parse next page URI from response headers: %w", err)
	}
	a.NextPage = nextPage

	return results, true, nil
}

// GetLineItem gets the currently launched AGS lineitem.
func (a *AGS) GetLineItem() (LineItem, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"}

	s := ServiceRequest{
		Scopes: scopes,
		Method: http.MethodGet,
		URI:    a.LineItem,
		Accept: "application/vnd.ims.lis.v2.lineitem+json",
	}

	_, body, err := a.Target.makeServiceRequest(s)
	if err != nil {
		return LineItem{}, fmt.Errorf("get lineitem make service request error: %w", err)
	}

	defer body.Close()
	var lineItem LineItem
	err = json.NewDecoder(body).Decode(&lineItem)
	if err != nil {
		return LineItem{}, fmt.Errorf("could not decode get lineitem response body: %w", err)
	}

	return lineItem, nil
}

// GetLineItems gets all the lineitems for the launched context, i.e. all columns in the course gradebook.
func (a *AGS) GetLineItems() ([]LineItem, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"}

	s := ServiceRequest{
		Scopes: scopes,
		Method: http.MethodGet,
		URI:    a.LineItems,
		Accept: "application/vnd.ims.lis.v2.lineitemcontainer+json",
	}

	_, body, err := a.Target.makeServiceRequest(s)
	if err != nil {
		return []LineItem{}, fmt.Errorf("get lineitems make service request error: %w", err)
	}

	defer body.Close()
	var lineItems []LineItem
	err = json.NewDecoder(body).Decode(&lineItems)
	if err != nil {
		return []LineItem{}, fmt.Errorf("could not decode get lineitems response body: %w", err)
	}

	return lineItems, nil
}

// UpdateLineItem sends an encoded LineItem used by the platform to update its definition of the launched lineitem, or
// the lineitem at the optional notLaunchedLineItemEndpoint parameter if updating the launched lineitem is not desired.
func (a *AGS) UpdateLineItem(lineItem LineItem, notLaunchedLineItemEndpoint string) (LineItem, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"}

	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(lineItem)
	if err != nil {
		return LineItem{}, fmt.Errorf("could not encode lineitem to update: %w", err)
	}

	var lineItemToUpdateURI *url.URL
	if notLaunchedLineItemEndpoint == "" {
		lineItemToUpdateURI = a.LineItem
	} else {
		lineItemToUpdateURI, err = url.Parse(notLaunchedLineItemEndpoint)
		if err != nil {
			return LineItem{}, fmt.Errorf("could not parse update endpoint URI: %w", err)
		}
	}

	s := ServiceRequest{
		Scopes:      scopes,
		Method:      http.MethodPut,
		URI:         lineItemToUpdateURI,
		Body:        &body,
		ContentType: "application/vnd.ims.lis.v2.lineitem+json",
		Accept:      "application/vnd.ims.lis.v2.lineitem+json",
	}

	_, responseBody, err := a.Target.makeServiceRequest(s)
	if err != nil {
		return LineItem{}, fmt.Errorf("update lineitem make service request error: %w", err)
	}

	defer responseBody.Close()
	var updatedLineItem LineItem
	err = json.NewDecoder(responseBody).Decode(&updatedLineItem)
	if err != nil {
		return LineItem{}, fmt.Errorf("could not decode update lineitem response body: %w", err)
	}

	return updatedLineItem, nil
}

// CreateLineItem creates a new gradebook column in the launched context's lineitems container.
func (a *AGS) CreateLineItem(lineItem LineItem) (LineItem, error) {
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"}

	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(lineItem)
	if err != nil {
		return LineItem{}, fmt.Errorf("could not encode lineitem to create: %w", err)
	}

	s := ServiceRequest{
		Scopes:      scopes,
		Method:      http.MethodPost,
		URI:         a.LineItems,
		Body:        &body,
		ContentType: "application/vnd.ims.lis.v2.lineitem+json",
		Accept:      "application/vnd.ims.lis.v2.lineitem+json",
	}

	_, responseBody, err := a.Target.makeServiceRequest(s)
	if err != nil {
		return LineItem{}, fmt.Errorf("create lineitem make service request error: %w", err)
	}

	defer responseBody.Close()
	var createdLineItem LineItem
	err = json.NewDecoder(responseBody).Decode(&createdLineItem)
	if err != nil {
		return LineItem{}, fmt.Errorf("could not decode update lineitem response body: %w", err)
	}

	return createdLineItem, nil
}

// DeleteLineItem removes a lineitem specified by the argument from the context's gradebook.
func (a *AGS) DeleteLineItem(lineItemToDeleteEndpoint string) error {
	if lineItemToDeleteEndpoint == "" {
		return errors.New("received empty lineitem to delete")
	}
	scopes := []string{"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"}

	lineItemToDeleteURI, err := url.Parse(lineItemToDeleteEndpoint)
	if err != nil {
		return fmt.Errorf("could not parse delete endpoint URI: %w", err)
	}

	s := ServiceRequest{
		Scopes: scopes,
		Method: http.MethodDelete,
		URI:    lineItemToDeleteURI,
	}

	_, _, err = a.Target.makeServiceRequest(s)
	if err != nil {
		return fmt.Errorf("update lineitem make service request error: %w", err)
	}

	return nil
}
