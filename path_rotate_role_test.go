package tfc

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestAcceptanceRotateRole tests rotating the API token for teams and orgs
func TestAcceptanceRotateRole(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add organization token role", acceptanceTestEnv.AddOrgTokenRole)
	t.Run("read organization token cred", acceptanceTestEnv.ReadOrgToken)
	t.Run("rotate organization token cred", acceptanceTestEnv.RotateToken)
	t.Run("rotate organization token cred", acceptanceTestEnv.VerifyTokenChange)
}

func (e *testEnv) RotateToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-org-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.Nil(t, resp)
}

func (e *testEnv) VerifyTokenChange(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-role/test-org-token",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.Nil(t, resp)

	rotateReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-org-token",
		Storage:   e.Storage,
	}
	resp, err = e.Backend.HandleRequest(e.Context, rotateReq)
	assert.False(t, (err != nil || (resp != nil && resp.IsError())), fmt.Sprintf("bad: resp: %#v\nerr:%v", resp, err))
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["token"])

	if tRaw, ok := resp.Data["token"]; ok {
		token := tRaw.(string)
		assert.NotEqual(t, e.SecretToken, token)
	} else {
		t.Fatalf("expected token, but found none")
	}
}
