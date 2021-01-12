package tfc

import (
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/testing/stepwise"
	dockerEnvironment "github.com/hashicorp/vault/sdk/testing/stepwise/environments/docker"
	"github.com/ryboe/q"
	"github.com/stretchr/testify/assert"
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
			assert.NotNil(t, resp)
			return nil
		},
	}
}

func testAccOrganizationRoleRead(t *testing.T, roleName, orgName string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "role/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			assert.NotNil(t, resp)
			assert.Equal(t, orgName, resp.Data["organization"])
			return nil
		},
	}
}

func testAccOrganizationCredRead(t *testing.T, roleName string, orgToken *string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "creds/" + roleName,
		Assert: func(resp *api.Secret, err error) error {
			assert.NotNil(t, resp)
			assert.NotEmpty(t, resp.Data["token"])
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
			q.Q("token at start of assert:", orgToken)
			assert.NotNil(t, resp)
			q.Q("resp token:", resp.Data["token"])
			assert.NotEmpty(t, resp.Data["token"])
			if *orgToken != "" {
				assert.Equal(t, *orgToken, resp.Data["token"].(string))
			} else {
				t.Fatal("expected orgToken to have a value")
			}
			return nil
		},
	}
}
