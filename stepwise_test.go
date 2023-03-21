// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"fmt"
	"os"
	"sync"
	"testing"

	stepwise "github.com/hashicorp/vault-testing-stepwise"
	dockerEnvironment "github.com/hashicorp/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestAccOrganizationToken(t *testing.T) {
	t.Parallel()
	if !runAcceptanceTests {
		t.SkipNow()
	}
	envOptions := &stepwise.MountOptions{
		RegistryName:    "tfc",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "vault-plugin-secrets-terraform",
		MountPathPrefix: "tfc",
	}

	roleName := "vault-stepwise-role"
	orgName := os.Getenv(envVarTerraformOrganization)
	cred := new(string)
	stepwise.Run(t, stepwise.Case{
		Precheck:    func() { testAccPreCheck(t) },
		Environment: dockerEnvironment.NewEnvironment("tfc", envOptions),
		Steps: []stepwise.Step{
			testAccConfig(t),
			testAccOrganizationRole(t, roleName, orgName),
			testAccOrganizationRoleRead(t, roleName, orgName),
			testAccOrganizationCredRead(t, roleName, cred),
			testAccOrganizationCredReRead(t, roleName, cred),
		},
	})
}

func TestAccUserToken(t *testing.T) {
	t.Parallel()
	if !runAcceptanceTests {
		t.SkipNow()
	}
	envOptions := &stepwise.MountOptions{
		RegistryName:    "tfc",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "vault-plugin-secrets-terraform",
		MountPathPrefix: "tfc",
	}

	roleName := "vault-stepwise-user-role"
	userID := os.Getenv(envVarTerraformUserID)
	cred := new(string)
	stepwise.Run(t, stepwise.Case{
		Precheck:    func() { testAccPreCheck(t) },
		Environment: dockerEnvironment.NewEnvironment("tfc", envOptions),
		Steps: []stepwise.Step{
			testAccConfig(t),
			testAccUserRole(t, roleName, userID),
			testAccUserRoleRead(t, roleName, userID),
			testAccUserCredReRead(t, roleName, cred),
			testAccUserCredReRead(t, roleName, cred),
		},
	})
}

var initSetup sync.Once

func testAccPreCheck(t *testing.T) {
	initSetup.Do(func() {
		// Ensure test variables are set
		if v := os.Getenv(envVarTerraformToken); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarTerraformToken))
		}
		if v := os.Getenv(envVarTerraformOrganization); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarTerraformOrganization))

		}
		if v := os.Getenv(envVarTerraformTeamID); v == "" {
			t.Skip(fmt.Printf("%s not set", envVarTerraformTeamID))

		}
	})
}

func testAccConfig(t *testing.T) stepwise.Step {
	address := "https://app.terraform.io"
	if v := os.Getenv(envVarTerraformAddress); v != "" {
		address = v
	}
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"token":   os.Getenv(envVarTerraformToken),
			"address": address,
		},
	}
}

func testAccOrganizationRole(t *testing.T, roleName, orgName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "role/" + roleName,
		Data: map[string]interface{}{
			"organization": orgName,
		},
		Assert: func(resp *api.Secret, err error) error {
			require.Nil(t, resp)
			require.Nil(t, err)
			return nil
		},
	}
}

func testAccOrganizationRoleRead(t *testing.T, roleName, orgName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "role/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.Equal(t, orgName, resp.Data["organization"])
			return nil
		},
	}
}

func testAccOrganizationCredRead(t *testing.T, roleName string, orgToken *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "creds/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Data["token"])
			*orgToken = resp.Data["token"].(string)
			return nil
		},
	}
}

func testAccOrganizationCredReRead(t *testing.T, roleName string, orgToken *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "creds/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Data["token"])
			if *orgToken != "" {
				require.Equal(t, *orgToken, resp.Data["token"].(string))
			} else {
				t.Fatal("expected orgToken to have a value")
			}
			return nil
		},
	}
}

func testAccUserRole(t *testing.T, roleName, userID string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "role/" + roleName,
		Data: map[string]interface{}{
			"user_id": userID,
			"ttl":     "1m",
			"max_ttl": "5m",
		},
		Assert: func(resp *api.Secret, err error) error {
			require.Nil(t, resp)
			require.Nil(t, err)
			return nil
		},
	}
}

func testAccUserRoleRead(t *testing.T, roleName, userID string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "role/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.Equal(t, userID, resp.Data["user_id"])
			return nil
		},
	}
}

func testAccUserCredReRead(t *testing.T, roleName string, userToken *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "creds/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Data["token"])
			if *userToken != "" {
				require.NotEqual(t, *userToken, resp.Data["token"].(string))
			}
			*userToken = resp.Data["token"].(string)
			return nil
		},
	}
}
