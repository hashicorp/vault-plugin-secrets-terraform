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
	// q.Q("--> should rotate role")
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

	// q.Q("creating token for:", roleEntry)
	token, err := b.createToken(ctx, req.Storage, name, roleEntry)
	// save token to role
	if err != nil {
		// q.Q("--> failed to rotate role:", err)
		// return logical.ErrorResponse(err.Error()), nil
		return nil, err
	}
	// q.Q("--> rotated role", name)

	roleEntry.Token = token

	if err := setTerraformRole(ctx, req.Storage, name, roleEntry); err != nil {
		// q.Q("--> failed to save updated role:", err)
		return nil, err
	}

	// q.Q("--> returning response")
	return &resp, nil
}

const pathRotateRoleHelpSyn = `
Request to rotate the credentials for a team or organization.
`
const pathRotateRoleHelpDesc = `
This path attempts to rotate the credentials for the given team or organization role
`
