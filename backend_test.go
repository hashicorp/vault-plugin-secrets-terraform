// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests           = "VAULT_ACC"
	envVarTerraformToken        = "TF_TOKEN"
	envVarTerraformOrganization = "TF_ORGANIZATION"
	envVarTerraformTeamID       = "TF_TEAM_ID"
	envVarTerraformUserID       = "TF_USER_ID"
	envVarTerraformAddress      = "TF_ADDRESS"
)

func getTestBackend(tb testing.TB) (*tfBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = &testSystemView{
		StaticSystemView: *logical.TestSystemView(),
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*tfBackend), config.StorageView
}

// testSystemView wraps a StaticSystemView so that the Rotation Manager
// deregister call issued on every config write succeeds. This mirrors Vault
// community edition, where DeregisterRotationJob is a no-op, and matches the
// test harness used by other rotation-enabled engines.
type testSystemView struct {
	logical.StaticSystemView
}

func (d testSystemView) DeregisterRotationJob(_ context.Context, _ *rotation.RotationJobDeregisterRequest) error {
	return nil
}

// replicationTestSystemView reports a replication state and counts Rotation
// Manager calls. Vault starts the Rotation Manager only on the active node, so
// on a performance standby the calls fail the same way they do in Vault.
type replicationTestSystemView struct {
	logical.StaticSystemView

	registerCalls   int
	deregisterCalls int
}

func (s *replicationTestSystemView) rotationManagerRunning() bool {
	return !s.ReplicationStateVal.HasState(consts.ReplicationPerformanceStandby)
}

func (s *replicationTestSystemView) rotationManagerCalls() int {
	return s.registerCalls + s.deregisterCalls
}

func (s *replicationTestSystemView) RegisterRotationJobWithResponse(_ context.Context, _ *rotation.RotationJobConfigureRequest) (*rotation.RotationInfo, error) {
	s.registerCalls++
	if !s.rotationManagerRunning() {
		return nil, errors.New("rotation manager is not initialized")
	}
	return &rotation.RotationInfo{
		RotationID:        "test-rotation-id",
		NextVaultRotation: time.Now().Add(time.Hour),
	}, nil
}

func (s *replicationTestSystemView) DeregisterRotationJob(_ context.Context, _ *rotation.RotationJobDeregisterRequest) error {
	s.deregisterCalls++
	if !s.rotationManagerRunning() {
		return errors.New("rotation manager is not initialized")
	}
	return nil
}

// getReplicationTestBackend returns a backend that acts as a cluster node with
// the given replication state. Backends created with the same storage share
// it, like the nodes of a cluster.
func getReplicationTestBackend(tb testing.TB, storage logical.Storage, state consts.ReplicationState, localMount bool) (*tfBackend, *replicationTestSystemView) {
	tb.Helper()

	sysView := &replicationTestSystemView{
		StaticSystemView: *logical.TestSystemView(),
	}
	sysView.ReplicationStateVal = state
	sysView.LocalMountVal = localMount

	config := logical.TestBackendConfig()
	config.StorageView = storage
	config.Logger = hclog.NewNullLogger()
	config.System = sysView

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*tfBackend), sysView
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
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"token": e.Token,
		},
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
			"organization": e.Organization,
			"team_id":      e.TeamID,
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
