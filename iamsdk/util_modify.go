// Copyright 2023 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamsdk

import (
	"encoding/json"
	"fmt"
	"strings"
)

// modifyOrganization is an encapsulation of permission CUD(Create, Update, Delete) operations.
// possible actions are `add-organization`, `update-organization`, `delete-organization`,
func (c *Client) modifyOrganization(action string, organization *Organization, columns []string) (*Response, bool, error) {
	if organization.Owner == "" {
		organization.Owner = "admin"
	}

	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", organization.Owner, organization.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	postBytes, err := json.Marshal(organization)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyApplication is an encapsulation of permission CUD(Create, Update, Delete) operations.
// possible actions are `add-application`, `update-application`, `delete-application`,
func (c *Client) modifyApplication(action string, application *Application, columns []string) (*Response, bool, error) {
	if application.Owner == "" {
		application.Owner = "admin"
	}

	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", application.Owner, application.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	postBytes, err := json.Marshal(application)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyProvider is an encapsulation of permission CUD(Create, Update, Delete) operations.
// possible actions are `add-provider`, `update-provider`, `delete-provider`,
func (c *Client) modifyProvider(action string, provider *Provider, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", provider.Owner, provider.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	provider.Owner = c.OrganizationName
	postBytes, err := json.Marshal(provider)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifySession is an encapsulation of permission CUD(Create, Update, Delete) operations.
// possible actions are `add-session`, `update-session`, `delete-session`,
func (c *Client) modifySession(action string, session *Session, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", session.Owner, session.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	session.Owner = c.OrganizationName
	postBytes, err := json.Marshal(session)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyUser is an encapsulation of user CUD(Create, Update, Delete) operations.
// possible actions are `add-user`, `update-user`, `delete-user`,
func (c *Client) modifyUser(action string, user *User, columns []string) (*Response, bool, error) {
	return c.modifyUserById(action, user.GetId(), user, columns)
}

func (c *Client) modifyUserById(action string, id string, user *User, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": id,
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	if user.Owner == "" {
		user.Owner = c.OrganizationName
	}
	postBytes, err := json.Marshal(user)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	if action == "check-user-password" {
		return resp, resp.Status == "ok", nil
	}

	return resp, resp.Data == "Affected", nil
}

func (c *Client) modifyUserByUserId(action string, owner string, userId string, user *User, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"owner":  owner,
		"userId": userId,
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	postBytes, err := json.Marshal(user)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	if action == "check-user-password" {
		return resp, resp.Status == "ok", nil
	}

	return resp, resp.Data == "Affected", nil
}

// modifyPermission is an encapsulation of permission CUD(Create, Update, Delete) operations.
// possible actions are `add-permission`, `update-permission`, `delete-permission`,
func (c *Client) modifyPermission(action string, permission *Permission, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", permission.Owner, permission.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	permission.Owner = c.OrganizationName
	postBytes, err := json.Marshal(permission)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyRole is an encapsulation of role CUD(Create, Update, Delete) operations.
// possible actions are `add-role`, `update-role`, `delete-role`,
func (c *Client) modifyRole(action string, role *Role, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", role.Owner, role.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	role.Owner = c.OrganizationName
	postBytes, err := json.Marshal(role)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyCert is an encapsulation of cert CUD(Create, Update, Delete) operations.
// possible actions are `add-cert`, `update-cert`, `delete-cert`,
func (c *Client) modifyCert(action string, cert *Cert, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", cert.Owner, cert.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	if cert.Owner == "" {
		cert.Owner = c.OrganizationName
	}
	postBytes, err := json.Marshal(cert)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyToken is an encapsulation of cert CUD(Create, Update, Delete) operations.
// possible actions are `add-token`, `update-token`, `delete-token`,
func (c *Client) modifyToken(action string, token *Token, columns []string) (*Response, bool, error) {
	token.Owner = "admin"

	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", token.Owner, token.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	postBytes, err := json.Marshal(token)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}

// modifyInvitation is an encapsulation of invitation CUD(Create, Update, Delete) operations.
// possible actions are `add-invitation`, `update-invitation`, `delete-invitation`,
func (c *Client) modifyInvitation(action string, invitation *Invitation, columns []string) (*Response, bool, error) {
	queryMap := map[string]string{
		"id": fmt.Sprintf("%s/%s", invitation.Owner, invitation.Name),
	}

	if len(columns) != 0 {
		queryMap["columns"] = strings.Join(columns, ",")
	}

	if invitation.Owner == "" {
		invitation.Owner = c.OrganizationName
	}
	postBytes, err := json.Marshal(invitation)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.DoPost(action, queryMap, postBytes, false, false)
	if err != nil {
		return nil, false, err
	}

	return resp, resp.Data == "Affected", nil
}
