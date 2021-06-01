// Copyright (c) 2021 MacEwan University. All rights reserved.
//
// This source code is licensed under the MIT-style license found in
// the LICENSE file in the root directory of this source tree.

// Package sql implements a persistent SQL data store. It implements the RegistrationStorer interface.
package sql

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/macewan-cs/lti/datastore"
)

type RegistrationFields struct {
	Issuer        string
	ClientID      string
	AuthTokenURI  string
	AuthLoginURI  string
	KeysetURI     string
	TargetLinkURI string
}

type DeploymentFields struct {
	Issuer       string
	DeploymentID string
}

type Config struct {
	RegistrationTable  string
	RegistrationFields RegistrationFields
	DeploymentTable    string
	DeploymentFields   DeploymentFields
}

type registrationIdentifiers struct {
	table  string
	fields string
	issuer string
}

type deploymentIdentifiers struct {
	table        string
	issuer       string
	deploymentID string
}

type Store struct {
	*sql.DB

	registration registrationIdentifiers
	deployment   deploymentIdentifiers
}

func NewConfig() Config {
	return Config{
		RegistrationTable: "registration",
		RegistrationFields: RegistrationFields{
			Issuer:        "issuer",
			ClientID:      "client_id",
			AuthTokenURI:  "auth_token_uri",
			AuthLoginURI:  "auth_login_uri",
			KeysetURI:     "keyset_uri",
			TargetLinkURI: "target_link_uri",
		},
		DeploymentTable: "deployment",
		DeploymentFields: DeploymentFields{
			Issuer:       "issuer",
			DeploymentID: "deployment_id",
		},
	}
}

func New(database *sql.DB, config Config) *Store {
	return &Store{
		DB: database,
		registration: registrationIdentifiers{
			table: config.RegistrationTable,
			fields: strings.Join([]string{
				// The strings must be joined in this order to
				// match their use with in the SQL queries.
				config.RegistrationFields.Issuer,
				config.RegistrationFields.ClientID,
				config.RegistrationFields.AuthTokenURI,
				config.RegistrationFields.AuthLoginURI,
				config.RegistrationFields.KeysetURI,
				config.RegistrationFields.TargetLinkURI,
			}, ","),
			issuer: config.RegistrationFields.Issuer,
		},
		deployment: deploymentIdentifiers{
			table:        config.DeploymentTable,
			issuer:       config.DeploymentFields.Issuer,
			deploymentID: config.DeploymentFields.DeploymentID,
		},
	}
}

func (s *Store) StoreRegistration(reg datastore.Registration) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}

	q := `INSERT INTO ` + s.registration.table + ` (` + s.registration.fields + `)
                   VALUES ($1, $2, $3, $4, $5, $6)`
	result, err := tx.Exec(q, reg.Issuer, reg.ClientID, reg.AuthTokenURI, reg.AuthLoginURI,
		reg.KeysetURI, reg.TargetLinkURI)
	if err != nil {
		tx.Rollback()
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		tx.Rollback()
		return err
	}

	if rowsAffected != 1 {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) FindRegistrationByIssuer(issuer string) (datastore.Registration, error) {
	if issuer == "" {
		return datastore.Registration{}, errors.New("received empty issuer argument")
	}

	q := `SELECT ` + s.registration.fields + `
                FROM ` + s.registration.table + `
               WHERE ` + s.registration.issuer + ` = $1`
	var (
		reg                                                  datastore.Registration
		authTokenURI, authLoginURI, keysetURI, targetLinkURI string
	)
	err := s.DB.QueryRow(q, issuer).Scan(&reg.Issuer, &reg.ClientID, &authTokenURI, &authLoginURI,
		&keysetURI, &targetLinkURI)
	if err != nil {
		if err == sql.ErrNoRows {
			return datastore.Registration{}, datastore.ErrRegistrationNotFound
		}
		return datastore.Registration{}, err
	}

	reg.AuthTokenURI, err = url.Parse(authTokenURI)
	if err != nil {
		return datastore.Registration{}, err
	}
	reg.AuthLoginURI, err = url.Parse(authLoginURI)
	if err != nil {
		return datastore.Registration{}, err
	}
	reg.KeysetURI, err = url.Parse(keysetURI)
	if err != nil {
		return datastore.Registration{}, err
	}
	reg.TargetLinkURI, err = url.Parse(targetLinkURI)
	if err != nil {
		return datastore.Registration{}, err
	}

	return reg, nil
}

func (s *Store) StoreDeployment(issuer, deploymentID string) error {
	if issuer == "" {
		return errors.New("received empty issuer argument")
	}
	if err := datastore.ValidateDeploymentID(deploymentID); err != nil {
		return fmt.Errorf("received invalid deployment ID: %v", err)
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}

	q := `INSERT INTO ` + s.deployment.table + ` (` + s.deployment.issuer + `,` + s.deployment.deploymentID + `)
                   VALUES ($1, $2)`
	result, err := tx.Exec(q, issuer, deploymentID)
	if err != nil {
		tx.Rollback()
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		tx.Rollback()
		return err
	}

	if rowsAffected != 1 {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

// FindDeployment looks up and returns either a Deployment by the issuer and deployment ID or the datastore error
// ErrDeploymentNotFound.
func (s *Store) FindDeployment(issuer, deploymentID string) (datastore.Deployment, error) {
	if issuer == "" {
		return datastore.Deployment{}, errors.New("received empty issuer argument")
	}
	if err := datastore.ValidateDeploymentID(deploymentID); err != nil {
		return datastore.Deployment{}, fmt.Errorf("received invalid deployment ID: %v", err)
	}

	q := `SELECT ` + s.deployment.deploymentID + `
                FROM ` + s.deployment.table + `
               WHERE ` + s.deployment.issuer + ` = $1
                 AND ` + s.deployment.deploymentID + ` = $2`
	deployment := datastore.Deployment{}
	err := s.DB.QueryRow(q, issuer, deploymentID).Scan(&deployment.DeploymentID)
	if err != nil {
		if err == sql.ErrNoRows {
			return datastore.Deployment{}, datastore.ErrRegistrationNotFound
		}
		return datastore.Deployment{}, err
	}

	return deployment, nil
}
