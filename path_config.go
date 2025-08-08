// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
)

const (
	configStoragePath = "config"
)

type tfConfig struct {
	automatedrotationutil.AutomatedRotationParams

	Token     string `json:"token"`
	TokenType string `json:"token_type,omitempty"`
	TokenID   string `json:"token_id,omitempty"`
	ID        string `json:"id,omitempty"`
	OldToken  string `json:"old_token,omitempty"`
	Address   string `json:"address"`
	BasePath  string `json:"base_path"`
}

func pathConfig(b *tfBackend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTerraformCloud,
		},
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The token to access Terraform Cloud",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token",
					Sensitive: true,
				},
			},
			"rotate_token_immediately": {
				Type:        framework.TypeBool,
				Description: "If true and rotation is setup, will immediately rotate the token provided to configuration. Only takes effect when writing the config.",
				Default:     true,
			},
			"token_type": {
				Type:        framework.TypeString,
				Description: "The type of token (organization, team, user). Required for rotation.",
			},
			"id": {
				Type:        framework.TypeString,
				Description: "The ID of the token. Required for rotation. Token IDs begin with `at-<>`.",
			},
			"old_token": {
				Type:        framework.TypeString,
				Description: "The behavior for handling the old token when rotating. Can be 'delete' or 'keep'. Defaults to 'delete'.",
				Default:     "delete",
			},
			"address": {
				Type: framework.TypeString,
				Description: `The address to access Terraform Cloud or Enterprise.
				Default is "https://app.terraform.io".`,
				Default: "https://app.terraform.io",
			},
			"base_path": {
				Type: framework.TypeString,
				Description: `The base path for the Terraform Cloud or Enterprise API.
				Default is "/api/v2/".`,
				Default: "/api/v2/",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}

	// Add automated rotation fields
	automatedrotationutil.AddAutomatedRotationFields(p.Fields)

	return p
}

func (b *tfBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *tfBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	configData := map[string]interface{}{
		"address":   config.Address,
		"base_path": config.BasePath,
	}

	if config.ShouldRegisterRotationJob() {
		config.PopulateAutomatedRotationData(configData)
		configData["token_type"] = config.TokenType
		configData["id"] = config.ID
		configData["old_token"] = config.OldToken

	}

	return &logical.Response{
		Data: configData,
	}, nil
}

func (b *tfBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(tfConfig)
	}

	if address, ok := data.GetOk("address"); ok {
		config.Address = address.(string)
	} else if req.Operation == logical.CreateOperation {
		config.Address = data.Get("address").(string)
	}

	if basePath, ok := data.GetOk("base_path"); ok {
		config.BasePath = basePath.(string)
	} else if req.Operation == logical.CreateOperation {
		config.BasePath = data.Get("base_path").(string)
	}

	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
	} else if req.Operation == logical.CreateOperation {
		config.Token = data.Get("token").(string)
	}

	// Parse automated rotation fields
	if err := config.ParseAutomatedRotationFields(data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var performedRotationManagerOperation string
	if config.ShouldDeregisterRotationJob() {
		performedRotationManagerOperation = rotation.PerformedDeregistration
		// Disable Automated Rotation and Deregister credentials if required
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}

		b.Logger().Debug("Deregistering rotation job", "mount", req.MountPoint+req.Path)
		if err := b.System().DeregisterRotationJob(ctx, deregisterReq); err != nil {
			return logical.ErrorResponse("error deregistering rotation job: %s", err), nil
		}
	} else if config.ShouldRegisterRotationJob() {
		performedRotationManagerOperation = rotation.PerformedRegistration
		// Register the rotation job if it's required.
		cfgReq := &rotation.RotationJobConfigureRequest{
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
			RotationPeriod:   config.RotationPeriod,
		}

		b.Logger().Debug("Registering rotation job", "mount", req.MountPoint+req.Path)
		if _, err = b.System().RegisterRotationJob(ctx, cfgReq); err != nil {
			return logical.ErrorResponse("error registering rotation job: %s", err), nil
		}

		// it should be possible to determine token type from the token itself
		// but the go-tfe library does not currently support this: https://github.com/hashicorp/go-tfe/blob/main/user.go#L47
		// so for now we will require the user to specify it
		if tokenType, ok := data.GetOk("token_type"); ok {
			config.TokenType = tokenType.(string)
		} else if req.Operation == logical.CreateOperation {
			config.TokenType = data.Get("token_type").(string)
		}

		if id, ok := data.GetOk("id"); ok {
			config.ID = id.(string)
		} else if req.Operation == logical.CreateOperation {
			config.ID = data.Get("id").(string)
		}

		// Validate token_type and id fields for rotation
		if config.TokenType != "" {
			if config.TokenType != "organization" && config.TokenType != "team" && config.TokenType != "user" {
				return logical.ErrorResponse("invalid token_type: must be 'organization', 'team', or 'user'"), nil
			}
			if config.ID == "" {
				return logical.ErrorResponse("id is required when token_type is specified"), nil
			}
		}

		if oldToken, ok := data.GetOk("old_token"); ok {
			config.OldToken = oldToken.(string)
			if config.OldToken != "delete" && config.OldToken != "keep" {
				return logical.ErrorResponse("invalid old_token: must be 'delete' or 'keep'"), nil
			}
		} else if req.Operation == logical.CreateOperation {
			config.OldToken = data.Get("old_token").(string)
		}
	}

	// Save the config
	if err := putConfigToStorage(ctx, req, config); err != nil {
		wrappedError := err
		if performedRotationManagerOperation != "" {
			b.Logger().Error("write to storage failed but the rotation manager still succeeded.",
				"operation", performedRotationManagerOperation, "mount", req.MountPoint, "path", req.Path)
			wrappedError = fmt.Errorf("write to storage failed but the rotation manager still succeeded; "+
				"operation=%s, mount=%s, path=%s, storageError=%s", performedRotationManagerOperation, req.MountPoint, req.Path, err)
		}
		return nil, wrappedError
	}

	// If rotation is enabled and the rotate_token_immediately flag is true,
	// rotate the token immediately.
	if config.ShouldRegisterRotationJob() && data.Get("rotate_token_immediately").(bool) {
		newToken, newID, err := rotateOnWrite(ctx, *config)
		if err != nil {
			b.Logger().Error("error immediately rotating token when writing backend configuration. rotation manager stil succeeded", "error", err)
			return nil, err
		}
		config.Token, config.ID = newToken, newID

		if err := putConfigToStorage(ctx, req, config); err != nil {
			b.Logger().Error("error immediately rotating token when writing backend configuration. rotation manager still succeeded", "error", err)
			return nil, fmt.Errorf("error writing updated config after immediate rotation: %w", err)
		}
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

func (b *tfBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func putConfigToStorage(ctx context.Context, req *logical.Request, config *tfConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func getConfig(ctx context.Context, s logical.Storage) (*tfConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(tfConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

func rotateOnWrite(ctx context.Context, config tfConfig) (string, string, error) {
	client, err := newClient(&config)
	if err != nil {
		return "", "", err
	}

	return client.RotateRootToken(ctx, config.TokenType, config.ID, config.OldToken)
}

const pathConfigHelpSynopsis = `Configure the Terraform Cloud / Enterprise backend.`

const pathConfigHelpDescription = `
The Terraform Cloud / Enterprise secret backend requires credentials for managing
organization and team tokens for Terraform Cloud or Enterprise. This endpoint
is used to configure those credentials and the default values for the backend in general.

You must specify a Terraform Cloud or Enterprise token with organization access
to allow Vault to create tokens.

If you are running Terraform Enterprise, you can specify the address and base path
for your instance and API endpoint.

Automatic token rotation (requires Vault Enterprise):
For automatic token rotation, specify:
- token_type: The type of token (organization, team, user)
- id: The ID of the organization, team, or user associated with the token
- old_token: How to handle the old token ("delete" or "keep", defaults to "delete")
- rotation_period or rotation_schedule: When to rotate the token

Example with rotation:
vault write terraform/config \
  token="your-token" \
  token_type="team" \
  id="at-123" \
  old_token="delete" \
  rotation_period="24h"
`
