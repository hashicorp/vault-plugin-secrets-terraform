package tfc

import (
	"context"

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
	var resp logical.Response

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		return logical.ErrorResponse("missing role entry"), nil
	}

	// TODO: verify team/org
	token, err := b.createToken(ctx, req.Storage, roleEntry)
	if err != nil {
		return nil, err
	}

	roleEntry.Token = token.Token

	if err := setTerraformRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return &resp, nil
}

const pathRotateRoleHelpSyn = `
Request to rotate the credentials for a team or organization.
`

const pathRotateRoleHelpDesc = `
This path attempts to rotate the credentials for the given team or organization role
`
