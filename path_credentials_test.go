package tfsecrets

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
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
	t.Run("renew organization token cred", acceptanceTestEnv.RenewOrgToken)
	t.Run("revoke organization token cred", acceptanceTestEnv.RevokeOrgToken)
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
	t.Run("renew team token cred", acceptanceTestEnv.RenewTeamToken)
	t.Run("revoke team token cred", acceptanceTestEnv.RevokeTeamToken)
}
