// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests           = "VAULT_ACC"
	envVarTerraformToken        = "TF_TOKEN"
	envVarTerraformOrganization = "TF_ORGANIZATION"
	envVarTerraformTeamID       = "TF_TEAM_ID"
	envVarTerraformUserID       = "TF_USER_ID"
	envVarTerraformAddress      = "TF_ADDRESS"
	// Rotation environment variables
	envVarTerraformTokenType = "TF_TOKEN_TYPE"
	envVarTerraformTokenID   = "TF_TOKEN_ID"
	envVarTerraformID        = "TF_ID"
)

func getTestBackend(tb testing.TB) (*tfBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*tfBackend), config.StorageView
}

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	Token        string
	Organization string
	TeamID       string
	UserID       string
	Description  string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the API token, for checking rotations
	SecretToken string

	// TokenIDs tracks the IDs of generated tokens, to make sure we clean up
	TokenIDs []string
}

func (e *testEnv) AddConfig(t *testing.T) {
	data := map[string]interface{}{
		"token": e.Token,
	}

	// Add rotation parameters if environment variables are set
	if tokenType := os.Getenv(envVarTerraformTokenType); tokenType != "" {
		data["token_type"] = tokenType
	}
	if id := os.Getenv(envVarTerraformID); id != "" {
		data["id"] = id
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data:      data,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) AddOrgTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-org-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"organization": e.Organization,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadOrgToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-org-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.NotNil(t, resp)
	require.Nil(t, err)
	require.NotEmpty(t, resp.Data["token"])

	if t, ok := resp.Data["token"]; ok {
		e.SecretToken = t.(string)
	}
	// verify there is a token
	b := e.Backend.(*tfBackend)
	client, err := b.getClient(e.Context, e.Storage)
	if err != nil {
		t.Fatal("fatal getting client")
	}
	ot, err := client.OrganizationTokens.Read(e.Context, e.Organization)
	if err != nil {
		t.Fatalf("unexpected error reading organization token: %s", err)
	}
	require.NotNil(t, ot)
}

func (e *testEnv) AddTeamLegacyTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-team-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"team_id":         e.TeamID,
			"credential_type": teamLegacyCredentialType,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.Nil(t, resp)
}

func (e *testEnv) ReadTeamLegacyToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-team-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Data["token"])

	// verify there is a token
	b := e.Backend.(*tfBackend)
	client, err := b.getClient(e.Context, e.Storage)
	if err != nil {
		t.Fatal("fatal getting client")
	}
	tt, err := client.TeamTokens.Read(e.Context, e.TeamID)
	if err != nil {
		t.Fatalf("unexpected error reading team token: %s", err)
	}
	require.NotNil(t, tt)
	if t, ok := resp.Data["token"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) AddMultiTeamTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-multiteam-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"team_id":         e.TeamID,
			"description":     e.Description,
			"credential_type": "team",
			"ttl":             "1m",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadMultiTeamToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-multiteam-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	if t, ok := resp.Data["token_id"]; ok {
		e.TokenIDs = append(e.TokenIDs, t.(string))
	}
	require.NotEmpty(t, resp.Data["token"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["token_id"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) CleanupMultiTeamTokens(t *testing.T) {
	if len(e.TokenIDs) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.TokenIDs))
	}

	for _, id := range e.TokenIDs {
		b := e.Backend.(*tfBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}
		if err := client.TeamTokens.DeleteByID(e.Context, id); err != nil {
			t.Fatalf("unexpected error deleting multiteam token: %s", err)
		}
	}
}

func (e *testEnv) AddUserTokenRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-user-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"user_id":     e.UserID,
			"description": e.Description,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadUserToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-user-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	if t, ok := resp.Data["token_id"]; ok {
		e.TokenIDs = append(e.TokenIDs, t.(string))
	}
	require.NotEmpty(t, resp.Data["token"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["token"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["token_id"]; ok {
		e.SecretToken = t.(string)
	}
}

func (e *testEnv) CleanupUserTokens(t *testing.T) {
	if len(e.TokenIDs) == 0 {
		t.Fatalf("expected 2 tokens, got: %d", len(e.TokenIDs))
	}

	for _, id := range e.TokenIDs {
		b := e.Backend.(*tfBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}
		if err := client.UserTokens.Delete(e.Context, id); err != nil {
			t.Fatalf("unexpected error deleting user token: %s", err)
		}
	}
}
