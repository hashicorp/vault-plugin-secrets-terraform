// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"
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

// RotateRootToken rotates the root token by creating a new token based on the
// token type and ID configured in the tfConfig.
func (c *client) RotateRootToken(ctx context.Context, tokenType, id, oldToken, currentToken string) (string, error) {
	if tokenType == "" || id == "" {
		return "", errors.New("token_type and id must be specified for token rotation")
	}

	var newToken string
	var err error

	switch tokenType {
	case "organization":
		newToken, err = c.rotateOrganizationToken(ctx, id)
	case "team":
		newToken, err = c.rotateTeamToken(ctx, id)
	case "user":
		newToken, err = c.rotateUserToken(ctx, id)
	default:
		return "", fmt.Errorf("unsupported token_type: %s", tokenType)
	}

	if err != nil {
		return "", err
	}

	if oldToken == "delete" && (tokenType == "team" || tokenType == "user") {
		if err := c.deleteToken(ctx, currentToken, tokenType); err != nil {
			return "", fmt.Errorf("failed to delete old token: %w", err)
		}
	}

	return newToken, nil
}

func (c *client) deleteToken(ctx context.Context, token, tokenType string) error {
	// Organization tokens are handled differently, so we only need to handle team and user tokens here
	if tokenType == "team" {
		return c.TeamTokens.Delete(ctx, token)
	} else if tokenType == "user" {
		return c.UserTokens.Delete(ctx, token)
	}
	return nil
}

func (c *client) rotateOrganizationToken(ctx context.Context, orgName string) (string, error) {
	// Generate a new organization token
	newToken, err := c.OrganizationTokens.Create(ctx, orgName)
	if err != nil {
		return "", fmt.Errorf("failed to generate new organization token: %w", err)
	}
	return newToken.Token, nil
}

func (c *client) rotateTeamToken(ctx context.Context, teamID string) (string, error) {
	// Generate a new team token
	newToken, err := c.TeamTokens.Create(ctx, teamID)
	if err != nil {
		return "", fmt.Errorf("failed to generate new team token: %w", err)
	}
	return newToken.Token, nil
}

func (c *client) rotateUserToken(ctx context.Context, userID string) (string, error) {
	// Create a new user token
	newToken, err := c.UserTokens.Create(ctx, userID, tfe.UserTokenCreateOptions{
		Description: "Rotated by Vault",
	})
	if err != nil {
		return "", fmt.Errorf("failed to create new user token: %w", err)
	}
	return newToken.Token, nil
}
