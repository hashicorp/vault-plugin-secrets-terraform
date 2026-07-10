// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

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

	// Writing a token triggers owner auto-discovery, so the create must point at
	// a Terraform API. The mock returns a user owner.
	m := newMockTFE(t, "users", "user-abc123", "/api/v2/authentication-tokens/at-abc123")

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"token":     "token123",
			"address":   m.server.URL,
			"base_path": "/api/v2/",
		})

		require.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"base_path":                  "/api/v2/",
			"address":                    m.server.URL,
			"explicit_max_ttl":           int64(0),
			"token_owner_type":           tokenOwnerTypeUser,
			"owner_id":                   "user-abc123",
			"rotation_schedule":          "",
			"rotation_window":            float64(0),
			"rotation_period":            float64(0),
			"rotation_policy":            "",
			"disable_automated_rotation": false,
		})

		require.NoError(t, err)

		// A token-only update is not part of this case; changing the address and
		// base_path without a token keeps the discovered owner metadata.
		err = testConfigUpdate(t, b, reqStorage, map[string]interface{}{
			"address":   "https://tfe.local",
			"base_path": "/v1/",
		})

		require.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"base_path":                  "/v1/",
			"address":                    "https://tfe.local",
			"explicit_max_ttl":           int64(0),
			"token_owner_type":           tokenOwnerTypeUser,
			"owner_id":                   "user-abc123",
			"rotation_schedule":          "",
			"rotation_window":            float64(0),
			"rotation_period":            float64(0),
			"rotation_policy":            "",
			"disable_automated_rotation": false,
		})

		require.NoError(t, err)

		err = testConfigDelete(t, b, reqStorage)

		require.NoError(t, err)
	})
}

// TestConfig_DiscoveryFailureFailsWrite verifies that a config write fails fast
// when Terraform cannot verify the token (auto-discovery fails), and that no
// configuration is persisted.
func TestConfig_DiscoveryFailureFailsWrite(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	// An empty resource type makes /account/details return no authenticated
	// resource, so discovery fails.
	m := newMockTFE(t, "", "", "")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"token":   "bad-token",
			"address": m.server.URL,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "expected an error response when discovery fails")

	cfg, err := getConfig(context.Background(), reqStorage)
	require.NoError(t, err)
	require.Nil(t, cfg, "config must not be persisted when discovery fails")
}

// TestConfig_TokenChangeRediscoversOwner verifies that replacing the token with
// a different owner type updates the stored owner metadata, so a later rotation
// acts on the correct owner.
func TestConfig_TokenChangeRediscoversOwner(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	ctx := context.Background()

	userMock := newMockTFE(t, "users", "user-abc123", "/api/v2/authentication-tokens/at-user")
	require.NoError(t, testConfigCreate(t, b, reqStorage, map[string]interface{}{
		"token":     "user-token",
		"address":   userMock.server.URL,
		"base_path": "/api/v2/",
	}))

	cfg, err := getConfig(ctx, reqStorage)
	require.NoError(t, err)
	require.Equal(t, tokenOwnerTypeUser, cfg.TokenOwnerType)
	require.Equal(t, "user-abc123", cfg.OwnerID)
	require.Equal(t, "at-user", cfg.TokenID)

	// Reconfigure with a team token pointing at a mock that returns a team owner.
	teamMock := newMockTFE(t, "teams", "team-xyz789", "/api/v2/authentication-tokens/at-team")
	require.NoError(t, testConfigUpdate(t, b, reqStorage, map[string]interface{}{
		"token":     "team-token",
		"address":   teamMock.server.URL,
		"base_path": "/api/v2/",
	}))

	cfg, err = getConfig(ctx, reqStorage)
	require.NoError(t, err)
	require.Equal(t, "team-token", cfg.Token)
	require.Equal(t, tokenOwnerTypeTeam, cfg.TokenOwnerType)
	require.Equal(t, "team-xyz789", cfg.OwnerID)
	require.Equal(t, "at-team", cfg.TokenID)
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
