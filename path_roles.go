package tfc

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	DynamicTeamTokenType  = "dynamic_team"
	TeamTokenType         = "team"
	UserTokenType         = "user"
	OrganizationTokenType = "organization"
)

// terraformRoleEntry is a Vault role construct that maps to TFC/TFE
type terraformRoleEntry struct {
	Name         string        `json:"name"`
	TokenType    string        `json:"token_type"`
	Organization string        `json:"organization,omitempty"`
	TeamID       string        `json:"team_id,omitempty"`
	UserID       string        `json:"user_id,omitempty"`
	TeamOptions  *TeamOptions  `json:"team_options,omitempty"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
	Token        string        `json:"token,omitempty"`
	TokenID      string        `json:"token_id,omitempty"`
}

type TeamOptions struct {
	OrganizationAccess *tfe.OrganizationAccessOptions `json:"organization_access,omitempty"`
	WorkspaceAccess    *[]WorkspaceAccess             `json:"workspace_access,omitempty"`
	Visibility         string                         `json:"visibility"`
}

type WorkspaceAccess struct {
	Workspace string                    `json:"workspace"`
	Options   *tfe.TeamAccessAddOptions `json:"options"`
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
	if r.TokenType != "" {
		respData["token_type"] = r.TokenType
	}
	if r.TeamOptions != nil {
		respData["team_options"] = r.TeamOptions
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
				"token_type": {
					Type:        framework.TypeString,
					Description: "Type of token generated for this role",
				},
				"organization": {
					Type:        framework.TypeString,
					Description: "Name of the Terraform Cloud or Enterprise organization",
				},
				"team_id": {
					Type:        framework.TypeString,
					Description: "ID of the Terraform Cloud or Enterprise team under organization (e.g., settings/teams/team-xxxxxxxxxxxxx)",
				},
				"user_id": {
					Type:        framework.TypeString,
					Description: "ID of the Terraform Cloud or Enterprise user (e.g., user-xxxxxxxxxxxxxxxx)",
				},
				"team_options": {
					Type:        framework.TypeString,
					Description: "JSON configuration of the Terraform Cloud teams created by this role",
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
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
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

	roleEntry, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &terraformRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)
	updateOperation := (req.Operation == logical.UpdateOperation)

	roleEntry.Name = name
	if tokenType, ok := d.GetOk("token_type"); ok {
		roleEntry.TokenType = tokenType.(string)
	} else if createOperation {
		roleEntry.TokenType = d.Get("token_type").(string)
	} else if updateOperation && roleEntry.TokenType != DynamicTeamTokenType {
		// For updates, if token_type is not passed in explicitly,
		// we will update the token_type based on the other field values.
		// To do this, we must override the old value if token_type is
		// not passed in explicitly. The exception to this is when the
		// token_type was 'dynamic_team', as this type needs to be explicitly
		// referenced. All other token types can be inferred.
		roleEntry.TokenType = ""
	}

	if organization, ok := d.GetOk("organization"); ok {
		roleEntry.Organization = organization.(string)
	} else if createOperation {
		roleEntry.Organization = d.Get("organization").(string)
	}

	if teamID, ok := d.GetOk("team_id"); ok {
		roleEntry.TeamID = teamID.(string)
	} else if createOperation {
		roleEntry.TeamID = d.Get("team_id").(string)
	}

	if userID, ok := d.GetOk("user_id"); ok {
		roleEntry.UserID = userID.(string)
	} else if createOperation {
		roleEntry.UserID = d.Get("user_id").(string)
	}

	// Parse the team_options
	if teamOptions, ok := d.GetOk("team_options"); ok {
		if teamOptions == "" {
			roleEntry.TeamOptions = nil
		} else {
			parsedOptions := &TeamOptions{}

			err := jsonutil.DecodeJSON([]byte(teamOptions.(string)), &parsedOptions)
			if err != nil {
				return logical.ErrorResponse("error parsing team_options '%s': %s", teamOptions.(string), err.Error()), nil
			}

			if parsedOptions.WorkspaceAccess == nil {
				w := make([]WorkspaceAccess, 0)
				parsedOptions.WorkspaceAccess = &w
			}
			roleEntry.TeamOptions = parsedOptions
		}
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

	var token *terraformToken
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	switch roleEntry.TokenType {
	case DynamicTeamTokenType:
		if roleEntry.UserID != "" || roleEntry.TeamID != "" {
			return logical.ErrorResponse(fmt.Sprintf("cannot provide user_id or team_id with token_type %q", DynamicTeamTokenType)), nil
		}
		if roleEntry.Organization == "" || roleEntry.TeamOptions == nil {
			return logical.ErrorResponse(fmt.Sprintf("must provide organization and team_options with token_type %q", DynamicTeamTokenType)), nil
		}
	case TeamTokenType:
		if roleEntry.UserID != "" || roleEntry.TeamOptions != nil {
			return logical.ErrorResponse(fmt.Sprintf("cannot provide user_id or team_options with token_type %q", TeamTokenType)), nil
		}
		if roleEntry.Organization == "" || roleEntry.TeamID == "" {
			return logical.ErrorResponse(fmt.Sprintf("must provide organization and team_id with token_type %q", TeamTokenType)), nil
		}

		// if we're creating a role to manage a team_id or organization token, we need to
		// create the token now. User tokens and dynamic team tokens will be created when
		// credentials are read.
		token, err = createTeamToken(ctx, client, roleEntry.TeamID)
		if err != nil {
			return nil, err
		}
	case UserTokenType:
		if roleEntry.Organization != "" || roleEntry.TeamID != "" || roleEntry.TeamOptions != nil {
			return logical.ErrorResponse(fmt.Sprintf("cannot provide organization or team_id or team_options with token_type %q", UserTokenType)), nil
		}
		if roleEntry.UserID == "" {
			return logical.ErrorResponse(fmt.Sprintf("must provide user_id with token_type %q", UserTokenType)), nil
		}
	case OrganizationTokenType:
		if roleEntry.UserID != "" || roleEntry.TeamID != "" || roleEntry.TeamOptions != nil {
			return logical.ErrorResponse(fmt.Sprintf("cannot provide user_id or team_id or team_options with token_type %q", OrganizationTokenType)), nil
		}
		if roleEntry.Organization == "" {
			return logical.ErrorResponse(fmt.Sprintf("must provide organization with token_type %q", OrganizationTokenType)), nil
		}

		// if we're creating a role to manage a team_id or organization token, we need to
		// create the token now. User tokens and dynamic team tokens will be created when
		// credentials are read.
		token, err = createOrgToken(ctx, client, roleEntry.Organization)
		if err != nil {
			return nil, err
		}
	default:
		if roleEntry.TeamOptions != nil {
			return logical.ErrorResponse(fmt.Sprintf("token_type must be %q if providing team_options", DynamicTeamTokenType)), nil
		}

		if roleEntry.UserID != "" && (roleEntry.Organization != "" || roleEntry.TeamID != "") {
			return logical.ErrorResponse("cannot provide a user_id in combination with organization or team_id"), nil
		}

		if roleEntry.UserID == "" && roleEntry.Organization == "" && roleEntry.TeamID == "" {
			return logical.ErrorResponse("must provide an organization name, team id, or user id if token_type is not specified"), nil
		}

		// if we're creating a role to manage a team_id or organization token, we need to
		// create the token now. User tokens and dynamic team tokens will be created when
		// credentials are read.
		if roleEntry.TeamID != "" {
			roleEntry.TokenType = TeamTokenType
			token, err = createTeamToken(ctx, client, roleEntry.TeamID)
			if err != nil {
				return nil, err
			}
		} else if roleEntry.Organization != "" {
			roleEntry.TokenType = OrganizationTokenType
			token, err = createOrgToken(ctx, client, roleEntry.Organization)
			if err != nil {
				return nil, err
			}
		} else {
			roleEntry.TokenType = UserTokenType
		}
	}

	if token != nil {
		roleEntry.Token = token.Token
		roleEntry.TokenID = token.ID
	}

	if err := setRole(ctx, req.Storage, name, roleEntry); err != nil {
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

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *terraformRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *tfBackend) getRole(ctx context.Context, s logical.Storage, name string) (*terraformRoleEntry, error) {
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

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Terraform Cloud / Enterprise tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Terraform Cloud /
Enterprise tokens. You can configure a role to manage an organization's token, a
team's token, dynamic team tokens, or a user's dynamic tokens.

A Terraform Cloud/Enterprise Organization can only have one active token at a
time. To manage an Organization's token, set the organization field and token_type to
'organization'.

A Terraform Cloud/Enterprise Team can only have one active token at a time. To
manage a Teams's token, set the team_id and organization fields and token_type to 'team'.

A Terraform Cloud/Enterprise Organization can have multiple teams. To have Vault create
teams and vend tokens for the team, set the team_options and organization fields and
token_type to 'dynamic_team'.

A Terraform Cloud/Enterprise User can have multiple API tokens. To manage a
User's token, set the user_id field and token_type to 'user'.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Terraform Cloud / Enterprise backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
