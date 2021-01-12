package tfc

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryboe/q"
	"github.com/stretchr/testify/assert"
)

const (
	envVarRunAccTests           = "VAULT_ACC"
	envVarTerraformToken        = "TF_TOKEN"
	envVarTerraformOrganization = "TF_ORGANIZATION"
	envVarTerraformTeamID       = "TF_TEAM_ID"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

type testEnv struct {
	Token        string
	Organization string
	TeamID       string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	MostRecentSecret *logical.Secret
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
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.Nil(t, resp)
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
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
}

func (e *testEnv) ReadOrgToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-org-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["token"])
	q.Q("Org token read:", resp)

	e.MostRecentSecret = resp.Secret

	// verify there is a token
	b := e.Backend.(*tfBackend)
	client, err := b.getClient(context.Background(), e.Storage)
	if err != nil {
		t.Fatal("fatal getting client")
	}
	ot, err := client.OrganizationTokens.Read(e.Context, e.Organization)
	if err != nil {
		t.Fatalf("unexpected error reading organization token: %s", err)
	}
	assert.NotNil(t, ot)
}

func (e *testEnv) AddTeamTokenRole(t *testing.T) {
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
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
}

func (e *testEnv) ReadTeamToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-team-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["token"])

	// verify there is a token
	b := e.Backend.(*tfBackend)
	client, err := b.getClient(context.Background(), e.Storage)
	if err != nil {
		t.Fatal("fatal getting client")
	}
	tt, err := client.TeamTokens.Read(e.Context, e.TeamID)
	if err != nil {
		t.Fatalf("unexpected error reading team token: %s", err)
	}
	assert.NotNil(t, tt)
	e.MostRecentSecret = resp.Secret
}
