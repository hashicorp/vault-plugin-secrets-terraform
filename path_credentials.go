package tfc

import (
	"context"
	"errors"

	"github.com/hashicorp/errwrap"
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
		Renew:  b.terraformTokenRenew,
		Revoke: b.terraformTokenRevoke,
	}
}

func (b *tfBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	role, err := b.credentialRead(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}

	if role == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createToken(ctx, req.Storage, roleName, role)
}

func (b *tfBackend) createToken(ctx context.Context, s logical.Storage, roleName string, roleEntry *terraformRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var token *terraformToken

	switch {
	case isOrgToken(roleEntry.Organization, roleEntry.TeamID):
		token, err = createOrgToken(ctx, client, roleEntry.Organization)
	case isTeamToken(roleEntry.Organization, roleEntry.TeamID):
		token, err = createTeamToken(ctx, client, roleEntry.TeamID)
	}

	if err != nil {
		return logical.ErrorResponse("Error creating Terraform token: %s", err), err
	}

	if token == nil {
		return nil, errors.New("error creating Terraform token")
	}

	resp := b.Secret(terraformTokenType).Response(map[string]interface{}{
		"token": token.Token,
	}, map[string]interface{}{
		"token_id":     token.ID,
		"organization": roleEntry.Organization,
		"team_id":      roleEntry.TeamID,
		"role":         roleName,
		"description":  token.Description,
	})

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}

	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

func (b *tfBackend) credentialRead(ctx context.Context, s logical.Storage, roleName string) (*terraformRoleEntry, error) {
	if roleName == "" {
		return nil, errors.New("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}

	var roleEntry terraformRoleEntry
	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	return nil, nil
}

const pathCredentialsHelpSyn = `
Generate a Terraform Cloud or Enterprise API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates Terraform Cloud or Enterprise API Organization or Team
Token based on a particular role.

If the role has the organization and team ID configured,
this path generates a team token.

If this role only has the organization configured, this path generates an
organization token.
`
