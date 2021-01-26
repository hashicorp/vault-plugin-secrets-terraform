package tfc

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// terraformRoleEntry is a Vault role construct that maps to TFC/TFE
type terraformRoleEntry struct {
	Name         string        `json:"name"`
	Organization string        `json:"organization,omitempty"`
	TeamID       string        `json:"team_id,omitempty"`
	UserID       string        `json:"user_id,omitempty"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
	Token        string        `json:"token,omitempty"`
	TokenID      string        `json:"token_id,omitempty"`
}

func (r *terraformRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"name":    r.Name,
		"ttl":     r.TTL.Seconds(),
		"max_ttl": r.MaxTTL.Seconds(),
	}
	if r.Organization != "" {
		respData["organization"] = r.Organization
	}
	if r.TeamID != "" {
		respData["team_id"] = r.TeamID
	}
	if r.UserID != "" {
		respData["user_id"] = r.UserID
	}
	return respData
}

func pathRole(b *tfBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"organization": {
					Type:        framework.TypeString,
					Description: "Name of the Terraform Cloud or Enterprise organization",
					Required:    true,
				},
				"team_id": {
					Type:        framework.TypeString,
					Description: "ID of the Terraform Cloud or Enterprise team under organization (e.g., settings/teams/team-xxxxxxxxxxxxx)",
				},
				"user_id": {
					Type:        framework.TypeString,
					Description: "ID of the Terraform Cloud or Enterprise user (e.g., user-xxxxxxxxxxxxxxxx)",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},

			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *tfBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *tfBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func (b *tfBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &terraformRoleEntry{}
	}

	roleEntry.Name = name
	if organization, ok := d.GetOk("organization"); ok {
		roleEntry.Organization = organization.(string)
	} else if organization != nil {
		roleEntry.Organization = d.Get("organization").(string)
	} else {
		roleEntry.Organization = ""
	}

	if teamID, ok := d.GetOk("team_id"); ok {
		roleEntry.TeamID = teamID.(string)
	} else if teamID != nil {
		roleEntry.TeamID = d.Get("team_id").(string)
	} else {
		roleEntry.TeamID = ""
	}

	if userID, ok := d.GetOk("user_id"); ok {
		roleEntry.UserID = userID.(string)
	} else if userID != nil {
		roleEntry.UserID = d.Get("user_id").(string)
	} else {
		roleEntry.UserID = ""
	}

	if (roleEntry.Organization != "" || roleEntry.TeamID != "") && roleEntry.UserID != "" {
		return logical.ErrorResponse("must provide one of user_id, team_id, or organization"), nil
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// if we're creating a role to manage a Team or Organization, we need to
	// create the token now. User tokens will be created when credentials are
	// read.
	if roleEntry.Organization != "" || roleEntry.TeamID != "" {
		token, err := b.createToken(ctx, req.Storage, roleEntry)
		if err != nil {
			return nil, err
		}

		roleEntry.Token = token.Token
		roleEntry.TokenID = token.ID
	}

	if err := setTerraformRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *tfBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting terraform role: %w", err)
	}

	return nil, nil
}

func setTerraformRole(ctx context.Context, s logical.Storage, name string, roleEntry *terraformRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("nil result writing to storage")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*terraformRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role terraformRoleEntry

	if entry != nil {
		if err := entry.DecodeJSON(&role); err != nil {
			return nil, err
		}
		return &role, nil
	}

	return nil, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Terraform Cloud / Enterprise tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Terraform Cloud / Enterprise tokens.
You can configure an organization token (for configuring an organization)
or a team token (for a team to plan and apply Terraform).

To configure a team token,
set the organization and team fields for the role.

To configure the organization
token, set the organization field.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Terraform Cloud / Enterprise backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
