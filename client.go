// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/go-tfe"
)

type client struct {
	*tfe.Client
}

type terraformToken struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Token       string    `json:"token"`
	ExpiredAt   time.Time `json:"expired_at,omitempty"`
}

// rootTokenDescription is applied to team and user root tokens created by Vault
// during rotation. Organization tokens do not support a description.
const rootTokenDescription = "Vault Terraform secrets engine root token"

func newClient(config *tfConfig) (*client, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	cfg := &tfe.Config{
		Address:  config.Address,
		BasePath: config.BasePath,
		Token:    config.Token,
	}

	tfc, err := tfe.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		tfc,
	}, nil
}

// explicitMaxTTLExpiry converts the configured explicit_max_ttl into the
// expiration passed to Terraform when creating a root token. A zero or negative
// value returns nil, which omits the expiration so Terraform applies its own
// default token expiry.
func explicitMaxTTLExpiry(ttl time.Duration) *time.Time {
	if ttl <= 0 {
		return nil
	}

	expiry := time.Now().Add(ttl)
	return &expiry
}

// createRootToken creates a replacement root token for the configured owner.
// Organization and team tokens use the options-based create so an expiration
// can be supplied; team and user tokens additionally carry a description so the
// token can be identified in Terraform.
func (c *client) createRootToken(ctx context.Context, ownerType, ownerID string, expiredAt *time.Time) (*terraformToken, error) {
	switch ownerType {
	case tokenOwnerTypeOrganization:
		token, err := c.OrganizationTokens.CreateWithOptions(ctx, ownerID, tfe.OrganizationTokenCreateOptions{
			ExpiredAt: expiredAt,
		})
		if err != nil {
			return nil, fmt.Errorf("error creating organization token: %w", err)
		}
		return &terraformToken{
			ID:        token.ID,
			Token:     token.Token,
			ExpiredAt: token.ExpiredAt,
		}, nil
	case tokenOwnerTypeTeam:
		// Terraform requires team token descriptions to be unique per team.
		// Rotation creates the replacement token before deleting the previous
		// one, so both briefly coexist; a unique suffix avoids colliding with the
		// outgoing token's description. This mirrors createTeamTokenWithOptions.
		description := fmt.Sprintf("%s(%d)", rootTokenDescription, rand.Intn(10000))
		token, err := c.TeamTokens.CreateWithOptions(ctx, ownerID, tfe.TeamTokenCreateOptions{
			Description: &description,
			ExpiredAt:   expiredAt,
		})
		if err != nil {
			return nil, fmt.Errorf("error creating team token: %w", err)
		}
		return &terraformToken{
			ID:          token.ID,
			Description: description,
			Token:       token.Token,
			ExpiredAt:   token.ExpiredAt,
		}, nil
	case tokenOwnerTypeUser:
		token, err := c.UserTokens.Create(ctx, ownerID, tfe.UserTokenCreateOptions{
			Description: rootTokenDescription,
			ExpiredAt:   expiredAt,
		})
		if err != nil {
			return nil, fmt.Errorf("error creating user token: %w", err)
		}
		return &terraformToken{
			ID:          token.ID,
			Description: token.Description,
			Token:       token.Token,
			ExpiredAt:   token.ExpiredAt,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported token owner type %q", ownerType)
	}
}

// validateRootToken performs a low-cost authenticated request to confirm the
// token configured on this client is valid.
func (c *client) validateRootToken(ctx context.Context) error {
	if _, err := c.readAccountDetails(ctx); err != nil {
		return fmt.Errorf("error validating token: %w", err)
	}
	return nil
}

// revokeRootToken deletes a previous team or user root token by its id. It is
// idempotent: deleting a token that no longer exists is treated as success so
// retries and recovery are safe. Organization tokens are implicitly replaced
// when a new one is created and require no revocation.
func (c *client) revokeRootToken(ctx context.Context, ownerType, tokenID string) error {
	if tokenID == "" {
		return nil
	}

	var err error

	switch ownerType {
	case tokenOwnerTypeTeam:
		err = c.TeamTokens.DeleteByID(ctx, tokenID)
	case tokenOwnerTypeUser:
		err = c.UserTokens.Delete(ctx, tokenID)
	default:
		return nil
	}

	if err != nil && !errors.Is(err, tfe.ErrResourceNotFound) {
		return err
	}

	return nil
}
