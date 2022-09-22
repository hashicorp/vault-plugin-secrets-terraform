package tfc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRole(b *tfBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the team or organization role",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRole,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
				},
			},

			HelpSynopsis:    pathRotateRoleHelpSyn,
			HelpDescription: pathRotateRoleHelpDesc,
		},
	}
}

func (b *tfBackend) pathRotateRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var token *terraformToken

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		return logical.ErrorResponse("missing role entry"), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	switch roleEntry.TokenType {
	case OrganizationTokenType:
		token, err = createOrgToken(ctx, client, roleEntry.Organization)
		if err != nil {
			return nil, err
		}
	case TeamTokenType:
		token, err = createTeamToken(ctx, client, roleEntry.TeamID)
		if err != nil {
			return nil, err
		}
	default:
		return logical.ErrorResponse(fmt.Sprintf("cannot rotate credentials for %q token_type", roleEntry.TokenType)), nil
	}

	roleEntry.Token = token.Token

	if err := setRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathRotateRoleHelpSyn = `
Request to rotate the credentials for a team or organization.
`

const pathRotateRoleHelpDesc = `
This path attempts to rotate the credentials for the given team or organization role. 
This endpoint returns an error if attempting to rotate a user role.
`
