// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

type tfConfig struct {
	automatedrotationutil.AutomatedRotationParams
	automatedrotationutil.RotationInfoResponseParams

	Token    string `json:"token"`
	Address  string `json:"address"`
	BasePath string `json:"base_path"`

	// ExplicitMaxTTL is the expiration set on the root token in Terraform
	// Cloud/Enterprise. The zero value omits the expiration on creation, which
	// causes Terraform to apply its default token expiry (2 years). It is an
	// upper-bound safety net; Vault owns the root token lifecycle.
	ExplicitMaxTTL time.Duration `json:"explicit_max_ttl"`

	// The following fields describe the configured root token and its owner.
	// They are discovered from Terraform Cloud/Enterprise at rotation time and
	// are not set directly by the operator.
	TokenOwnerType string `json:"token_owner_type,omitempty"`
	OwnerID        string `json:"owner_id,omitempty"`
	TokenID        string `json:"token_id,omitempty"`
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
			"explicit_max_ttl": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `The maximum lifetime (expiration) set on the root token in
				Terraform Cloud or Enterprise. Acts as an upper-bound safety net; Vault
				manages the root token lifecycle. The default (0) omits the expiration
				so Terraform applies its default token expiry (2 years). The same value
				is used for both manual and automatic rotation.`,
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

	// Add the standard automated rotation fields (rotation_schedule,
	// rotation_window, rotation_period, disable_automated_rotation, and
	// rotation_policy). Automated rotation relies on the Rotation Manager, which
	// is only available in Vault Enterprise; setting any of these fields in Vault
	// community edition returns an error when the rotation job is registered.
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

	// The token is intentionally not returned by this endpoint.
	configData := map[string]interface{}{
		"address":          config.Address,
		"base_path":        config.BasePath,
		"explicit_max_ttl": int64(config.ExplicitMaxTTL.Seconds()),
	}

	if config.TokenOwnerType != "" {
		configData["token_owner_type"] = config.TokenOwnerType
	}
	if config.OwnerID != "" {
		configData["owner_id"] = config.OwnerID
	}

	config.PopulateAutomatedRotationData(configData)

	// last_vault_rotation and next_vault_rotation are only meaningful once a
	// rotation has occurred or a rotation job has been registered. Omit them
	// while unset to avoid returning null values.
	config.PopulateRotationInfo(configData)
	if configData["last_vault_rotation"] == nil {
		delete(configData, "last_vault_rotation")
	}
	if configData["next_vault_rotation"] == nil {
		delete(configData, "next_vault_rotation")
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

	// address and base_path fall back to the stored value on update and to the
	// schema default on create, so a token-only update does not reset them and
	// discovery runs against the correct endpoint.
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

	if explicitMaxTTLRaw, ok := data.GetOk("explicit_max_ttl"); ok {
		config.ExplicitMaxTTL = time.Duration(explicitMaxTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		config.ExplicitMaxTTL = time.Duration(data.Get("explicit_max_ttl").(int)) * time.Second
	}

	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)

		// Auto-discover the token owner from Terraform Cloud/Enterprise. This
		// verifies the token and records the owner metadata used for rotation. A
		// discovery failure fails the write so an invalid or misconfigured token
		// surfaces immediately instead of at first rotation. Rediscovering
		// whenever the token is written also keeps the owner metadata correct
		// when the token is replaced with a different type (for example, user to
		// team).
		if err := discoverAndSetOwner(ctx, config); err != nil {
			return logical.ErrorResponse("failed to verify the configured token with Terraform: %s", err), nil
		}
	}

	// Register or deregister the Rotation Manager job based on the supplied
	// rotation fields. HandleRotationJob also parses the automated rotation
	// fields, so they are not parsed separately here. In Vault community edition
	// this returns an error if any rotation field is set, because the Rotation
	// Manager is only available in Vault Enterprise.
	rotationResp, err := config.HandleRotationJob(ctx, b.Backend, data, req)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	config.SetRotationInfo(rotationResp.RotationInfo)

	err = writeConfig(ctx, req.Storage, config)
	if storageErr := rotationResp.HandleStorageErrorAfterRotationJob(req, err); storageErr != nil {
		return nil, storageErr
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

// discoverAndSetOwner verifies the configured token against Terraform
// Cloud/Enterprise and records the discovered owner metadata on config. The
// token id is empty on older Terraform Enterprise that does not expose the
// auth-token link; rotation warns to revoke the initial token manually in that
// case.
func discoverAndSetOwner(ctx context.Context, config *tfConfig) error {
	c, err := newClient(config)
	if err != nil {
		return fmt.Errorf("error building client: %w", err)
	}

	ownerType, ownerID, tokenID, err := c.discoverTokenOwner(ctx)
	if err != nil {
		return err
	}

	config.TokenOwnerType = ownerType
	config.OwnerID = ownerID
	config.TokenID = tokenID
	return nil
}

func (b *tfBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
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

func writeConfig(ctx context.Context, s logical.Storage, config *tfConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
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
`
