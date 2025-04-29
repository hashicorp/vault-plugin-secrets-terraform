// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

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
		UserID:       os.Getenv(envVarTerraformUserID),
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

func TestAcceptanceTeamLegacyToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add team token role", acceptanceTestEnv.AddTeamLegacyTokenRole)
	t.Run("read team token cred", acceptanceTestEnv.ReadTeamLegacyToken)
}

func TestAcceptanceMultiTeamToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add multiteam token role", acceptanceTestEnv.AddMultiTeamTokenRole)
	t.Run("read multiteam token cred", acceptanceTestEnv.ReadMultiTeamToken)
	t.Run("read multiteam token cred", acceptanceTestEnv.ReadMultiTeamToken)
	t.Run("cleanup multiteam tokens", acceptanceTestEnv.CleanupMultiTeamTokens)
}

func TestAcceptanceUserToken(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add user token role", acceptanceTestEnv.AddUserTokenRole)
	t.Run("read user token cred", acceptanceTestEnv.ReadUserToken)
	t.Run("read user token cred", acceptanceTestEnv.ReadUserToken)
	t.Run("cleanup user tokens", acceptanceTestEnv.CleanupUserTokens)
}
