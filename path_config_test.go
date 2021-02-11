package tfc

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"token": "token123",
		})

		require.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"base_path": "/api/v2/",
			"address":   "https://app.terraform.io",
		})

		require.NoError(t, err)

		err = testConfigUpdate(t, b, reqStorage, map[string]interface{}{
			"address":   "https://tfe.local",
			"base_path": "/v1/",
		})

		require.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"base_path": "/v1/",
			"address":   "https://tfe.local",
		})

		require.NoError(t, err)

		err = testConfigDelete(t, b, reqStorage)

		require.NoError(t, err)
	})
}

func testConfigDelete(t *testing.T, b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}
