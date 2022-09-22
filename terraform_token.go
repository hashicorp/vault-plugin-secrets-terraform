package tfc

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	teamNamePrefix     = "vault-"
	terraformTokenType = "terraform_token"
)

func createTeam(ctx context.Context, c *client, organization string, opts *TeamOptions) (string, error) {
	if _, err := c.Organizations.Read(ctx, organization); err != nil {
		return "", fmt.Errorf("failed to read organization %s: %w", organization, err)
	}

	name, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate uuid: %w", err)
	}

	name = teamNamePrefix + name

	teamOptions := tfe.TeamCreateOptions{
		Name:               &name,
		Visibility:         &opts.Visibility,
		OrganizationAccess: opts.OrganizationAccess,
	}

	team, err := c.Teams.Create(ctx, organization, teamOptions)
	if err != nil {
		return "", fmt.Errorf("failed to create team in organization %s: %w", organization, err)
	}

	for _, w := range *opts.WorkspaceAccess {
		workspace, err := c.Workspaces.Read(ctx, organization, w.Workspace)
		if err != nil {
			return "", fmt.Errorf("failed to read workspace %s in organization %s: %w", w.Workspace, organization, err)
		}

		teamAccessOptions := w.Options
		teamAccessOptions.Team = team
		teamAccessOptions.Workspace = workspace

		_, err = c.TeamAccess.Add(ctx, *teamAccessOptions)
		if err != nil {
			return "", fmt.Errorf("failed to add team access for team %s and workspace %s in organization %s with attributes %v: %w", team.ID, workspace.Name, organization, w, err)
		}
	}
	return team.ID, nil
}

func createOrgToken(ctx context.Context, c *client, organization string) (*terraformToken, error) {
	if _, err := c.Organizations.Read(ctx, organization); err != nil {
		return nil, err
	}

	token, err := c.OrganizationTokens.Create(ctx, organization)
	if err != nil {
		return nil, fmt.Errorf("failed to create token for organization %s: %w", organization, err)
	}

	return &terraformToken{
		ID:          token.ID,
		Description: token.Description,
		Token:       token.Token,
	}, nil
}

func createTeamToken(ctx context.Context, c *client, teamID string) (*terraformToken, error) {
	if _, err := c.Teams.Read(ctx, teamID); err != nil {
		return nil, err
	}

	token, err := c.TeamTokens.Create(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to create token for organization %s: %w", teamID, err)
	}

	return &terraformToken{
		ID:          token.ID,
		Description: token.Description,
		Token:       token.Token,
	}, nil
}

func createUserToken(ctx context.Context, c *client, userID string) (*terraformToken, error) {
	token, err := c.UserTokens.Create(ctx, userID, tfe.UserTokenCreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create token for user %s: %w", userID, err)
	}

	return &terraformToken{
		ID:          token.ID,
		Description: token.Description,
		Token:       token.Token,
	}, nil
}

func (b *tfBackend) terraformTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	tokenType := ""
	tokenTypeRaw, ok := req.Secret.InternalData["token_type"]
	if ok {
		tokenType, ok = tokenTypeRaw.(string)
		if !ok || tokenType == "" {
			return nil, fmt.Errorf("invalid value for token_type in secret internal data")
		}
	}

	switch tokenType {
	case OrganizationTokenType:
		organization := ""
		organizationRaw, ok := req.Secret.InternalData["organization"]
		if ok {
			organization, ok = organizationRaw.(string)
			if !ok || organization == "" {
				return nil, fmt.Errorf("invalid value for organization in secret internal data")
			}
		}
		// revoke org API token
		if err := client.OrganizationTokens.Delete(ctx, organization); err != nil {
			return nil, fmt.Errorf("failed to revoke token for organization %s: %w", organization, err)
		}
		return nil, nil
	case DynamicTeamTokenType:
		teamID := ""
		teamIDRaw, ok := req.Secret.InternalData["team_id"]
		if ok {
			teamID, ok = teamIDRaw.(string)
			if !ok || teamID == "" {
				return nil, fmt.Errorf("invalid value for team_id in secret internal data")
			}
		}
		// delete team - this will delete token as well
		if err := client.Teams.Delete(ctx, teamID); err != nil {
			return nil, fmt.Errorf("failed to delete team %s: %w", teamID, err)
		}
		return nil, nil
	case TeamTokenType:
		teamID := ""
		teamIDRaw, ok := req.Secret.InternalData["team_id"]
		if ok {
			teamID, ok = teamIDRaw.(string)
			if !ok || teamID == "" {
				return nil, fmt.Errorf("invalid value for team_id in secret internal data")
			}
		}
		// revoke team API token
		if err := client.TeamTokens.Delete(ctx, teamID); err != nil {
			return nil, fmt.Errorf("failed to revoke token for team %s: %w", teamID, err)
		}
		return nil, nil
	default:
		// if we haven't returned yet, then the token is a user API token
		tokenID := ""
		tokenIDRaw, ok := req.Secret.InternalData["token_id"]
		if ok {
			tokenID, ok = tokenIDRaw.(string)
			if !ok || tokenID == "" {
				return nil, fmt.Errorf("invalid value for token_id in secret internal data")
			}
		}

		if err := client.UserTokens.Delete(ctx, tokenID); err != nil {
			return nil, fmt.Errorf("failed to revoke user token: %w", err)
		}
		return nil, nil
	}
}

func (b *tfBackend) terraformTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
