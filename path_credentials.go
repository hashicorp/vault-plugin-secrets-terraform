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
		Revoke: b.terraformTokenRevoke,
	}
}

func (b *tfBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	// b.lock.Lock()
	// defer b.lock.Unlock()

	role, err := b.credentialRead(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}

	if role == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	var token string
	// if we already have a token, return that
	makeToken := true
	if (role.Organization != "" || role.TeamID != "") && role.UserID == "" {
		// role.token != "" {
		if role.Token != "" {
			makeToken = false
			token = role.Token
			// }
		}
	}

	if makeToken {
		// token, err = b.createToken(ctx, req.Storage, roleName, role)
		// // save token to role
		// if err != nil {
		// 	// return logical.ErrorResponse(err.Error()), nil
		// 	return nil, err
		// }

		// role.Token = token

		// if err := setTerraformRole(ctx, req.Storage, roleName, role); err != nil {
		// 	return nil, err
		// }
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token":        token,
			"organization": role.Organization,
			"team_id":      role.TeamID,
			"role":         role.Name,
		},
	}
	return resp, nil
}

func (b *tfBackend) createToken(ctx context.Context, s logical.Storage, roleName string, roleEntry *terraformRoleEntry) (string, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		// return logical.ErrorResponse(err.Error()), nil
		return "", err
	}

	var token *terraformToken

	switch {
	case isOrgToken(roleEntry.Organization, roleEntry.TeamID):
		token, err = createOrgToken(ctx, client, roleEntry.Organization)
	case isTeamToken(roleEntry.TeamID):
		token, err = createTeamToken(ctx, client, roleEntry.TeamID)
	}

	if err != nil {
		// return logical.ErrorResponse("Error creating Terraform token: %s", err), err
		return "", errwrap.Wrapf("error creating Terraform token: {{err}}", err)
	}

	if token == nil {
		return "", errors.New("error creating Terraform token")
	}

	return token.Token, nil
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
