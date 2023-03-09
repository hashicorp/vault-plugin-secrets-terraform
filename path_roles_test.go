// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	roleName   = "testtfc"
	testTTL    = int64(120)
	testMaxTTL = int64(3600)
)

func checkEnvVars(t *testing.T, envVar string) string {
	v, check := os.LookupEnv(envVar)
	if !check {
		t.Fatalf("Error: required environment variable %s is not set", envVar)
	}

	return v
}

func TestTokenRole(t *testing.T) {
	b, s := getTestBackend(t)

	organization := checkEnvVars(t, envVarTerraformOrganization)
	teamID := checkEnvVars(t, envVarTerraformTeamID)
	_ = checkEnvVars(t, "TFE_TOKEN")

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			resp, err := testTokenRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"organization": organization,
				},
			)
			if resp.IsError() {
				t.Fatalf("Error: received error response: %v", resp.Error().Error())
			}
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Test Token Roles", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"organization": organization,
		})
		require.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		if resp == nil {
			t.Fatalf("Error: received nil response")
		}

		require.NoError(t, err)
		require.Equal(t, roleName, resp.Data["name"])
		require.Equal(t, organization, resp.Data["organization"])
		require.Empty(t, resp.Data["team_id"])

		resp, err = testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"team_id": teamID,
			"ttl":     testTTL,
			"max_ttl": testMaxTTL,
		})
		require.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		require.NoError(t, err)
		require.Equal(t, roleName, resp.Data["name"])
		require.Equal(t, teamID, resp.Data["team_id"])
		require.Equal(t, float64(testTTL), resp.Data["ttl"])
		require.Equal(t, float64(testMaxTTL), resp.Data["max_ttl"])

		_, err = testTokenRoleDelete(t, b, s)
		require.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		require.NoError(t, err)
		require.Nil(t, err)
	})

	t.Run("Create Team Token Role", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"organization": organization,
			"team_id":      teamID,
		})
		require.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		if resp == nil {
			t.Fatalf("Error: received nil response")
		}

		require.NoError(t, err)
		require.Equal(t, roleName, resp.Data["name"])
		require.Equal(t, organization, resp.Data["organization"])
		require.Equal(t, teamID, resp.Data["team_id"])
	})
}

func TestUserRole(t *testing.T) {
	b, s := getTestBackend(t)

	organization := checkEnvVars(t, envVarTerraformOrganization)
	teamID := checkEnvVars(t, envVarTerraformTeamID)
	userID := checkEnvVars(t, envVarTerraformUserID)

	t.Run("Create User Role - fail", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"organization": organization,
			// user_id cannot be combined with organization or team
			"user_id": teamID,
		})
		require.Nil(t, err)

		require.Error(t, resp.Error())
	})
	t.Run("Create User Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"user_id": userID,
			"max_ttl": "3600",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["user_id"], userID)
	})
	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Re-read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["user_id"], userID)
	})
}

// Utility function to create a role while, returning any response (including errors)
func testTokenRoleCreate(t *testing.T, b *tfBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
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
func testUserTokenRead(t *testing.T, b *tfBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + roleName,
		Storage:   s,
	})
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
