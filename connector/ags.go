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
)

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
