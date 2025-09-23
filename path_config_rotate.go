// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigRotate(b *tfBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/rotate",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixTerraformCloud,
				OperationVerb:   "rotate",
				OperationSuffix: "config",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: framework.OperationFunc(func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
						return nil, b.rotateRootToken(ctx, req)
					}),
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},

			HelpSynopsis:    pathRotateConfigHelpSyn,
			HelpDescription: pathRotateConfigHelpDesc,
		},
	}
}

// RotateRootToken rotates the root token by creating a new token based on the
// token type and ID configured in the tfConfig.
func (b *tfBackend) rotateRootToken(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("Rotating configuration token")
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("error getting client: %w", err)

	}

	oldTokenID := config.TokenID
	if config.TokenType == "" || config.ID == "" || oldTokenID == "" {
		return errors.New("token_type, token_id, and id must be specified for token rotation")
	}

	var newToken string
	var newID string

	switch config.TokenType {
	case "organization":
		newToken, newID, err = b.rotateOrganizationToken(ctx, client, config.ID)
	case "team":
		newToken, newID, err = b.rotateTeamToken(ctx, client, config.ID)
	case "user":
		newToken, newID, err = b.rotateUserToken(ctx, client, config.ID)
	default:
		return fmt.Errorf("unsupported token_type: %s", config.TokenType)
	}

	if err != nil {
		return err
	}

	config.Token, config.TokenID = newToken, newID
	if err := putConfigToStorage(ctx, req, config); err != nil {
		b.Logger().Error("error saving new config after rotation: %v", err)
		return fmt.Errorf("error saving new config after rotation: %w", err)
	}

	if config.OldToken == "delete" && (config.TokenType == "team" || config.TokenType == "user") {
		if err := b.deleteToken(ctx, client, oldTokenID, config.TokenType); err != nil {
			return fmt.Errorf("failed to delete old token: %w", err)
		}
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil
}

func (b *tfBackend) deleteToken(ctx context.Context, c *client, id, tokenType string) error {
	if tokenType == "team" {
		return c.TeamTokens.DeleteByID(ctx, id)
	} else if tokenType == "user" {
		return c.UserTokens.Delete(ctx, id)
	}
	return nil
}

func (b *tfBackend) rotateOrganizationToken(ctx context.Context, c *client, orgName string) (string, string, error) {
	b.Logger().Debug("Creating new organization token for ", orgName)
	newToken, err := c.OrganizationTokens.Create(ctx, orgName)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new organization token: %w", err)
	}
	return newToken.Token, newToken.ID, nil
}

func (b *tfBackend) rotateTeamToken(ctx context.Context, c *client, teamID string) (string, string, error) {
	desc := generateRandomDescriptionString("Rotated by Vault")
	b.Logger().Debug("Creating new team token with description:", teamID, desc)
	newToken, err := c.TeamTokens.CreateWithOptions(ctx, teamID, tfe.TeamTokenCreateOptions{
		Description: &desc,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new team token: %w", err)
	}
	return newToken.Token, newToken.ID, nil
}

func (b *tfBackend) rotateUserToken(ctx context.Context, c *client, userID string) (string, string, error) {
	desc := generateRandomDescriptionString("Rotated by Vault")
	b.Logger().Debug("Creating new user token with description:", userID, desc)

	newToken, err := c.UserTokens.Create(ctx, userID, tfe.UserTokenCreateOptions{
		Description: desc,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create new user token: %w", err)
	}
	return newToken.Token, newToken.ID, nil
}

func generateRandomDescriptionString(description string) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	result := make([]byte, 5)
	for i := range result {
		result[i] = chars[r.Intn(len(chars))]
	}

	return fmt.Sprintf("%s (%s)", description, string(result))
}

const pathRotateConfigHelpSyn = `
Request to rotate the root token for a user, team, or organization.
`

const pathRotateConfigHelpDesc = `
This path attempts to rotate the root token of the secret engine configuration.
Rotation requires that the token_type, id, and token_id fields are set in the
configuration. If the old_token field is set to "delete" and the token_type is
set to "team" or "user", the old token will be deleted after a successful rotation.

Automatic rotation can be configured by setting the rotation_period field in the
configuration. If rotation is configured, the token will be rotated automatically
after the specified period has elapsed. Automatic rotation is only supported for 
Vault Enterprise.
`
