// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"strings"
	"sync"
	"time"

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
	lock sync.RWMutex
	// rotationLock serializes the entire root-token rotation operation so a
	// manual rotation and an automated Rotation Manager rotation cannot
	// interleave. It must be distinct from lock, which guards the client cache
	// and is taken by getClient and reset (both called during rotation).
	rotationLock sync.Mutex
	client       *client
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
				pathRotateRoot(&b),
			},
			pathRotateRole(&b),
		),
		Secrets: []*framework.Secret{
			b.terraformToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
		// RotateCredential is invoked by the Rotation Manager (Vault Enterprise)
		// to perform scheduled root-token rotation. It shares the same core
		// implementation as the manual rotate-root endpoint.
		RotateCredential: func(ctx context.Context, req *logical.Request) error {
			_, err := b.rotateRootToken(ctx, req)
			return err
		},
		// WALRollback reconciles a root-token rotation that was interrupted by a
		// crash or failover. WALRollbackMinAge is longer than a rotation takes,
		// so an in-flight rotation's WAL is never rolled back prematurely.
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,
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

const backendHelp = `
The Terraform Cloud secrets backend dynamically generates organization
and user tokens.

After mounting this backend, credentials to manage Terraform Cloud or
Enterprise tokens must be configured with the "config/" endpoints.
`
