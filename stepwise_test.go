package tfc

import (
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/testing/stepwise"
	dockerEnvironment "github.com/hashicorp/vault/sdk/testing/stepwise/environments/docker"
	"github.com/stretchr/testify/require"
)

func TestAccOrganizationToken(t *testing.T) {
	t.Parallel()
	if !runAcceptanceTests {
		t.SkipNow()
	}
	envOptions := &stepwise.MountOptions{
		RegistryName:    "tfc",
		PluginType:      stepwise.PluginTypeSecrets,
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
		PluginType:      stepwise.PluginTypeSecrets,
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
		if v := os.Getenv("TEST_TF_ADDRESS"); v == "" {
			t.Skip("TEST_TF_TOKEN not set")
		}
		if v := os.Getenv("TEST_TF_TOKEN"); v == "" {
			t.Skip("TEST_TF_TOKEN not set")
		}
		if v := os.Getenv("TEST_TF_ORGANIZATION"); v == "" {
			t.Skip("TEST_TF_ORGANIZATION not set")
		}
		if v := os.Getenv("TEST_TF_TEAM_ID"); v == "" {
			t.Skip("TEST_TF_TEAM_ID not set")
		}
	})
}
func testAccConfig(t *testing.T) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"token":   os.Getenv("TEST_TF_TOKEN"),
			"address": os.Getenv("TEST_TF_ADDRESS"),
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
