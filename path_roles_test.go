package tfc

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	roleName     = "testtfc"
	organization = "testing-org"
	teamID       = "team-asdfasdfasdfa"
	testTTL      = int64(120)
	testMaxTTL   = int64(3600)
)

func TestTokenRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"organization": organization + strconv.Itoa(i),
				},
			)
			assert.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		assert.NoError(t, err)
		assert.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Test Token Roles", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"organization": organization,
		})
		assert.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		assert.NoError(t, err)
		assert.Equal(t, roleName, resp.Data["name"])
		assert.Equal(t, organization, resp.Data["organization"])
		assert.Equal(t, "", resp.Data["team_id"])

		resp, err = testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"team_id": teamID,
			"ttl":     testTTL,
			"max_ttl": testMaxTTL,
		})
		assert.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		assert.NoError(t, err)
		assert.Equal(t, roleName, resp.Data["name"])
		assert.Equal(t, organization, resp.Data["organization"])
		assert.Equal(t, teamID, resp.Data["team_id"])
		assert.Equal(t, float64(testTTL), resp.Data["ttl"])
		assert.Equal(t, float64(testMaxTTL), resp.Data["max_ttl"])

		_, err = testTokenRoleDelete(t, b, s)
		assert.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		assert.NoError(t, err)
		assert.Nil(t, err)
	})

	t.Run("Create Team Token Role", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"organization": organization,
			"team_id":      teamID,
		})
		assert.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		assert.NoError(t, err)
		assert.Equal(t, roleName, resp.Data["name"])
		assert.Equal(t, organization, resp.Data["organization"])
		assert.Equal(t, teamID, resp.Data["team_id"])
	})
}

// Utility function to create a role while, returning any response (including errors)
func testTokenRoleCreate(t *testing.T, b *tfBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

func testTokenRoleUpdate(t *testing.T, b *tfBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + roleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors
func testTokenRoleRead(t *testing.T, b *tfBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors
func testTokenRoleList(t *testing.T, b *tfBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors
func testTokenRoleDelete(t *testing.T, b *tfBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}
