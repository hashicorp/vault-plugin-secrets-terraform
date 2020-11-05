package tfsecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

var maxWALAge = 24 * time.Hour

type walEntry struct {
	Role         string
	Organization string    `mapstructure:"organization"`
	TeamID       string    `mapstructure:"team_id"`
	TokenID      string    `mapstructure:"token_id"`
	Expiration   time.Time `mapstructure:"expiration"`
}

func (b *tfBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != terraformTokenType {
		return fmt.Errorf("unknown rollback type %q", kind)
	}

	var entry walEntry
	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	if isOrgToken(entry.Organization, entry.TeamID) {
		if _, err := client.OrganizationTokens.Read(ctx, entry.Organization); err != nil {
			return err
		}

		if err := client.OrganizationTokens.Delete(ctx, entry.Organization); err != nil {
			return err
		}
		return nil
	}

	if isTeamToken(entry.Organization, entry.TeamID) {
		if _, err := client.TeamTokens.Read(ctx, entry.TeamID); err != nil {
			return err
		}

		if err := client.TeamTokens.Delete(ctx, entry.TeamID); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("Token %s not found, not deleting", entry.TokenID)
}
