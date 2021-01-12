package tfc

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/testing/stepwise"
	"github.com/ryboe/q"

	dockerEnvironment "github.com/hashicorp/vault/sdk/testing/stepwise/environments/docker"
)

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Token:        os.Getenv(envVarTerraformToken),
		Organization: os.Getenv(envVarTerraformOrganization),
		TeamID:       os.Getenv(envVarTerraformTeamID),
		Backend:      b,
		Context:      ctx,
		Storage:      &logical.InmemStorage{},
	}, nil
}

func TestAcceptanceOrganizationToken(t *testing.T) {
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
}

func TestAcceptanceTeamToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add team token role", acceptanceTestEnv.AddTeamTokenRole)
	t.Run("read team token cred", acceptanceTestEnv.ReadTeamToken)
}

func TestOrganizationToken(t *testing.T) {
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

	// roleName := "vault-stepwise-role"
	stepwise.Run(t, stepwise.Case{
		Precheck:    func() { testAccStepwisePreCheck(t) },
		Environment: dockerEnvironment.NewEnvironment("tfc", envOptions),
		Steps: []stepwise.Step{
			testAccStepwiseConfig(t),
			// testAccStepwiseOrganizationRole(t, roleName),
			// testAccStepwiseRead(t, "creds", roleName, []credentialTestFunc{listDynamoTablesTest}),
		},
	})
}

var initSetup sync.Once

func testAccStepwisePreCheck(t *testing.T) {
	initSetup.Do(func() {
		if v := os.Getenv("TEST_TF_ADDRESS"); v == "" {
			t.Skip("TEST_TF_TOKEN not set")
		}

		// Ensure test variables are set
		if v := os.Getenv("TEST_TF_TOKEN"); v == "" {
			t.Skip("TEST_TF_TOKEN not set")
		}
	})
}
func testAccStepwiseConfig(t *testing.T) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "config",
		Data: map[string]interface{}{
			"token":   os.Getenv("TEST_TF_TOKEN"),
			"address": os.Getenv("TEST_TF_ADDRESS"),
		},
	}
}
func testAccStepwiseReadConfig(t *testing.T) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "config",
		Assert: func(resp *api.Secret, err error) error {
			q.Q("read config resp:", resp)
			return nil
		},
	}
}
