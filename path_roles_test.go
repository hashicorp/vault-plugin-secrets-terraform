// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
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
	if !runAcceptanceTests {
		t.SkipNow()
	}

	b, s := getTestBackend(t)

	organization := checkEnvVars(t, envVarTerraformOrganization)
	teamID := checkEnvVars(t, envVarTerraformTeamID)
	token := checkEnvVars(t, envVarTerraformToken)

	// Create a configuration with the right API token
	err := testConfigCreate(t, b, s, map[string]interface{}{
		"token": token,
	})
	if err != nil {
		t.Fatal(fmt.Errorf("err creating config, err=%w", err))
	}

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

	t.Run("Test Legacy Team Token Role - Fail", func(t *testing.T) {
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
		require.Nil(t, err)

		require.Error(t, resp.Error())
	})

	t.Run("Test Legacy Team Token Role", func(t *testing.T) {
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
		})
		require.Error(t, resp.Error())

		// require.NoError(t, err)

		resp, err = testTokenRoleRead(t, b, s)
		require.NoError(t, err)
		require.Equal(t, roleName, resp.Data["name"])
		require.Equal(t, teamID, resp.Data["team_id"])

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

func TestMultiTeamRole(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	b, s := getTestBackend(t)

	teamID := checkEnvVars(t, envVarTerraformTeamID)

	descriptionOriginal := "description1"
	descriptionUpdated := "description2"

	t.Run("Create MultiTeam Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"team_id":         teamID,
			"credential_type": "team",
			"max_ttl":         "3600",
			"description":     descriptionOriginal,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Read MultiTeam Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["team_id"], teamID)
		require.Equal(t, resp.Data["description"], descriptionOriginal) // cred description includes random int
	})
	t.Run("Update MultiTeam Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"credential_type": "team",
			"ttl":             "1m",
			"max_ttl":         "5h",
			"description":     descriptionUpdated,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Re-read MultiTeam Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["team_id"], teamID)
		require.Equal(t, resp.Data["description"], descriptionUpdated)
	})
}

func TestUserRole(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	b, s := getTestBackend(t)

	organization := checkEnvVars(t, envVarTerraformOrganization)
	teamID := checkEnvVars(t, envVarTerraformTeamID)
	userID := checkEnvVars(t, envVarTerraformUserID)
	descriptionOriginal := "description1"
	descriptionUpdated := "description2"

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
			"user_id":     userID,
			"max_ttl":     "3600",
			"description": descriptionOriginal,
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
		require.Equal(t, resp.Data["description"], descriptionOriginal)
	})
	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":         "1m",
			"max_ttl":     "5h",
			"description": descriptionUpdated,
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
		require.Equal(t, resp.Data["description"], descriptionUpdated)
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
