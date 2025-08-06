// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

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
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output\"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v\"`, k, expectedV, actualV)
		}
	}

	return nil
}

// TestConfig_Rotation tests the rotation functionality.
// This is an acceptance test that requires valid credentials.
func TestConfig_Rotation(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	tokenType := os.Getenv(envVarTerraformTokenType)
	id := os.Getenv(envVarTerraformID)
	token := os.Getenv(envVarTerraformToken)

	if tokenType == "" || id == "" || token == "" {
		t.Skipf("Skipping rotation test, set %s, %s, and %s to run", envVarTerraformTokenType, envVarTerraformID, envVarTerraformToken)
	}

	b, reqStorage := getTestBackend(t)

	t.Run("Test Token Rotation", func(t *testing.T) {
		// Create a config with rotation parameters
		configData := map[string]interface{}{
			"token":      token,
			"token_type": tokenType,
			"id":         id,
		}

		err := testConfigCreate(t, b, reqStorage, configData)
		require.NoError(t, err)

		// Store original token for comparison
		originalToken := token

		// Trigger rotation using the RotateCredential function
		err = b.RotateCredential(context.Background(), &logical.Request{
			Storage: reqStorage,
		})
		require.NoError(t, err)

		// Read the config again and verify the token has changed
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   reqStorage,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotEqual(t, token, resp.Data["token"])
	})
}

