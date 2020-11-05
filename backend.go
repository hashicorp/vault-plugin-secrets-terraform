package tfsecrets

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const minUserRollbackAge = 5 * time.Minute

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
	var b = tfBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.terraformToken(),
		},
		BackendType:       logical.TypeLogical,
		Invalidate:        b.invalidate,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: minUserRollbackAge,
	}

	return &b
}

func (b *tfBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *tfBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
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
