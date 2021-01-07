package tfc

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

func getTestBackend(tb testing.TB) (*tfBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*tfBackend), config.StorageView
}
