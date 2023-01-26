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

func TestDynamicTokenRole(t *testing.T) {
	b, s := getTestBackend(t)

	organization := checkEnvVars(t, envVarTerraformOrganization)

	t.Run("Create Dynamic Token Role - fail", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			// Need 'token_type' to be 'dynamic_team'
			"organization": organization,
			"team_options": "{\"visibility\": \"secret\"}",
		})
		require.Nil(t, err)

		require.Error(t, resp.Error())
	})
	t.Run("Create Dynamic Token Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			// Need 'token_type' to be 'dynamic_team'
			"organization": organization,
			"team_options": "{\"visibility\": \"secret\"}",
			"token_type":   "dynamic_team",
			"max_ttl":      "3600",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Read Dynamic Team Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, DynamicTeamTokenType, resp.Data["token_type"])
	})
	t.Run("Update Dynamic Team Role - fail", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			// token_type is still 'dynamic_team' so passing in 'team_id' will fail.
			"team_id": "test",
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)

		require.Error(t, resp.Error())
	})
	t.Run("Update Dynamic Team Role - pass", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"team_options": "{\"visibility\": \"organization\"}",
			"ttl":          "1m",
			"max_ttl":      "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Re-read Dynamic Team Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, DynamicTeamTokenType, resp.Data["token_type"])
	})
	t.Run("Change to 'organization' token_type", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"token_type":   "organization",
			"team_options": "",
			"ttl":          "1m",
			"max_ttl":      "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})
	t.Run("Re-read Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, OrganizationTokenType, resp.Data["token_type"])
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
		require.Equal(t, resp.Data["token_type"], UserTokenType)
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
		require.Equal(t, resp.Data["token_type"], UserTokenType)
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
