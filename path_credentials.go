package tfc

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *tfBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},

		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

func (b *tfBackend) terraformToken() *framework.Secret {
	return &framework.Secret{
		Type: terraformTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Terraform Token",
			},
		},
		Revoke: b.terraformTokenRevoke,
		Renew:  b.terraformTokenRenew,
	}
}

func (b *tfBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	switch roleEntry.TokenType {
	case UserTokenType:
		return b.createUserCreds(ctx, req, roleEntry)
	case DynamicTeamTokenType:
		return b.createDynamicTeamCreds(ctx, req, roleEntry)
	default:
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token_id":     roleEntry.TokenID,
			"token":        roleEntry.Token,
			"token_type":   roleEntry.TokenType,
			"organization": roleEntry.Organization,
			"team_id":      roleEntry.TeamID,
			"role":         roleEntry.Name,
		},
	}
	return resp, nil
}

func (b *tfBackend) createDynamicTeamCreds(ctx context.Context, req *logical.Request, role *terraformRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	teamID, err := createTeam(ctx, client, role.Organization, role.TeamOptions)
	if err != nil {
		return nil, err
	}

	token, err := createTeamToken(ctx, client, teamID)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(terraformTokenType).Response(map[string]interface{}{
		"token":    token.Token,
		"token_id": token.ID,
	}, map[string]interface{}{
		"token_id":   token.ID,
		"role":       role.Name,
		"team_id":    teamID,
		"token_type": role.TokenType,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *tfBackend) createUserCreds(ctx context.Context, req *logical.Request, role *terraformRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	token, err := createUserToken(ctx, client, role.UserID)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(terraformTokenType).Response(map[string]interface{}{
		"token":    token.Token,
		"token_id": token.ID,
	}, map[string]interface{}{
		"token_id":   token.ID,
		"role":       role.Name,
		"token_type": role.TokenType,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

const pathCredentialsHelpSyn = `
Generate a Terraform Cloud or Enterprise API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates Terraform Cloud or Enterprise API Organization, Team, or
User Tokens based on a particular role. A role can only represent a single type
of Token; Organization, Team, or User, and so can only contain one parameter for
organization, team_id, or user_id.

If the role has the team ID configured, this path generates a team token.

If this role only has the organization configured, this path generates an
organization token.

If this role has a user ID configured, this path generates a user token.
`
