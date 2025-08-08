// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// operationPrefixTerraformCloud is used as a prefix for OpenAPI operation id's.
const operationPrefixTerraformCloud = "terraform-cloud"

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type tfBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client
}

func backend() *tfBackend {
	b := tfBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
			pathRotateRole(&b),
		),
		Secrets: []*framework.Secret{
			b.terraformToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
		RotateCredential: func(ctx context.Context, req *logical.Request) error {
			_, err := b.rotateRoot(ctx, req)
			return err
		},
	}

	return &b
}

func (b *tfBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *tfBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *tfBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if b.client == nil {
		if config == nil {
			config = new(tfConfig)
		}
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

func (b *tfBackend) rotateRoot(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config.Token == "" {
		return logical.ErrorResponse("backend is missing token"), nil
	}

	if config.TokenType == "" || config.ID == "" {
		return logical.ErrorResponse("token_type and id must be configured for token rotation"), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	token, newID, err := client.RotateRootToken(ctx, config.TokenType, config.ID, config.OldToken)
	if err != nil {
		return nil, fmt.Errorf("error rotating root token: %w", err)
	}

	config.Token = token
	config.ID = newID

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

const backendHelp = `
The Terraform Cloud secrets backend dynamically generates organization
and user tokens.

After mounting this backend, credentials to manage Terraform Cloud or
Enterprise tokens must be configured with the "config/" endpoints.
`
