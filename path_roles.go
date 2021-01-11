package tfc

import (
	"context"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// terraformRoleEntry is a Vault role construct that maps to TFC/TFE
type terraformRoleEntry struct {
	Name         string        `json:"name"`
	Organization string        `json:"organization"`
	TeamID       string        `json:"team_id"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}

func (r terraformRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"name":         r.Name,
		"organization": r.Organization,
		"team_id":      r.TeamID,
		"ttl":          r.TTL.Seconds(),
		"max_ttl":      r.MaxTTL.Seconds(),
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
	var resp logical.Response

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()
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
	} else if req.Operation == logical.CreateOperation {
		roleEntry.Organization = d.Get("organization").(string)
		if roleEntry.Organization == "" {
			return logical.ErrorResponse("missing organization"), nil
		}
	}

	if team, ok := d.GetOk("team_id"); ok {
		roleEntry.TeamID = team.(string)
	} else if team != nil {
		roleEntry.TeamID = d.Get("team_id").(string)
	} else {
		roleEntry.TeamID = ""
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

	if err := setTerraformRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (b *tfBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, errwrap.Wrapf("error deleting terraform role: {{err}}", err)
	}

	return nil, nil
}

func setTerraformRole(ctx context.Context, s logical.Storage, name string, roleEntry *terraformRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return errwrap.Wrapf("nil result writing to storage", nil)
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func saveRole(ctx context.Context, s logical.Storage, c *terraformRoleEntry, name string) error {
	entry, err := logical.StorageEntryJSON("role/"+name, c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, s logical.Storage, name string) (*terraformRoleEntry, error) {
	if name == "" {
		return nil, errwrap.Wrapf("missing role name", nil)
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

const pathRoleHelpSynopsis = `Manages the Vault role for generating Terraform Cloud / Enterprise tokens.`
const pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Terraform Cloud / Enterprise tokens.
You can configure an organization token (for configuring an organization)
or a team token (for a team to plan and apply Terraform).

To configure a team token,
set the organization and team fields for the role.

To configure the organization
token, set the organization field.
`

const pathRoleListHelpSynopsis = `List the existing roles in Terraform Cloud / Enterprise backend`
const pathRoleListHelpDescription = `Roles will be listed by the role name.`
