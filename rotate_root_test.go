// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestExplicitMaxTTLExpiry(t *testing.T) {
	require.Nil(t, explicitMaxTTLExpiry(0), "zero ttl should omit expiration")
	require.Nil(t, explicitMaxTTLExpiry(-time.Hour), "negative ttl should omit expiration")

	got := explicitMaxTTLExpiry(time.Hour)
	require.NotNil(t, got)
	require.WithinDuration(t, time.Now().Add(time.Hour), *got, time.Minute)
}

// mockTFE is a minimal Terraform Cloud/Enterprise API used to exercise the
// rotation flow without real credentials.
type mockTFE struct {
	server *httptest.Server

	// resourceType is the JSON:API type returned by /account/details, e.g.
	// "users", "teams", or "organizations".
	resourceType string
	ownerID      string
	// authTokenLink, when set, is returned as data.links.auth-token so the
	// engine can discover the id of the configured token.
	authTokenLink string

	mu          sync.Mutex
	deletedIDs  []string
	createdPath string
}

func newMockTFE(t *testing.T, resourceType, ownerID, authTokenLink string) *mockTFE {
	t.Helper()

	m := &mockTFE{
		resourceType:  resourceType,
		ownerID:       ownerID,
		authTokenLink: authTokenLink,
	}

	mux := http.NewServeMux()

	// Ping is called by go-tfe when a client is constructed.
	mux.HandleFunc("/api/v2/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// account/details is decoded as plain JSON by the engine.
	mux.HandleFunc("/api/v2/account/details", func(w http.ResponseWriter, r *http.Request) {
		links := ""
		if m.authTokenLink != "" {
			links = fmt.Sprintf(`,"links":{"auth-token":%q}`, m.authTokenLink)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, `{"data":{"id":%q,"type":%q,"relationships":{"authenticated-resource":{"data":{"id":%q,"type":%q}}}%s}}`,
			m.ownerID, m.resourceType, m.ownerID, m.resourceType, links)
	})

	// Token creation endpoints (org singular, team/user plural).
	tokenCreate := func(newID, newToken string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			m.mu.Lock()
			m.createdPath = r.URL.Path
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/vnd.api+json")
			fmt.Fprint(w, tokenJSONAPI(newID, newToken, rootTokenDescription))
		}
	}
	mux.HandleFunc("/api/v2/organizations/"+ownerID+"/authentication-token", tokenCreate("at-new-org", "new-org-token"))
	mux.HandleFunc("/api/v2/teams/"+ownerID+"/authentication-tokens", tokenCreate("at-new-team", "new-team-token"))
	mux.HandleFunc("/api/v2/users/"+ownerID+"/authentication-tokens", tokenCreate("at-new-user", "new-user-token"))

	// Token deletion by id.
	mux.HandleFunc("/api/v2/authentication-tokens/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v2/authentication-tokens/")
		m.mu.Lock()
		m.deletedIDs = append(m.deletedIDs, id)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)

	return m
}

func (m *mockTFE) deleted() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.deletedIDs...)
}

func tokenJSONAPI(id, token, description string) string {
	return fmt.Sprintf(`{"data":{"id":%q,"type":"authentication-tokens","attributes":{`+
		`"token":%q,"description":%q,"created-at":"2020-01-01T00:00:00Z",`+
		`"expired-at":"2020-01-01T00:00:00Z","last-used-at":"2020-01-01T00:00:00Z"}}}`,
		id, token, description)
}

func writeRotationTestConfig(t *testing.T, b *tfBackend, s logical.Storage, address string) {
	t.Helper()

	err := testConfigCreate(t, b, s, map[string]interface{}{
		"token":     "secret-zero-token",
		"address":   address,
		"base_path": "/api/v2/",
	})
	require.NoError(t, err)
}

func rotateRoot(t *testing.T, b *tfBackend, s logical.Storage) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "rotate-root returned error response: %v", resp.Error())
	return resp
}

func TestRotateRoot_User_WithAuthTokenLink(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "/api/v2/authentication-tokens/at-old-user")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	resp := rotateRoot(t, b, storage)

	require.Empty(t, resp.Warnings, "id was known, so no secret-zero warning expected")
	require.Equal(t, tokenOwnerTypeUser, resp.Data["token_owner_type"])
	require.Equal(t, "user-abc", resp.Data["owner_id"])

	// The previous token (discovered from the auth-token link) is revoked.
	require.Equal(t, []string{"at-old-user"}, m.deleted())

	// Storage now holds the new token and its id.
	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, "new-user-token", config.Token)
	require.Equal(t, "at-new-user", config.TokenID)
	require.Equal(t, tokenOwnerTypeUser, config.TokenOwnerType)
	require.False(t, config.LastVaultRotation.IsZero())
}

func TestRotateRoot_User_SecretZeroUnknown(t *testing.T) {
	b, storage := getTestBackend(t)
	// No auth-token link: simulates older Terraform Enterprise.
	m := newMockTFE(t, "users", "user-abc", "")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	resp := rotateRoot(t, b, storage)

	require.Len(t, resp.Warnings, 1, "expected a secret-zero warning")
	require.Contains(t, resp.Warnings[0], "manually")
	require.Empty(t, m.deleted(), "no token id known, so nothing should be revoked")

	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, "new-user-token", config.Token)
	require.Equal(t, "at-new-user", config.TokenID)
}

func TestRotateRoot_SecondRotation_RevokesTrackedToken(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	// First rotation: secret zero unknown, warns, tracks at-new-user.
	first := rotateRoot(t, b, storage)
	require.Len(t, first.Warnings, 1)
	require.Empty(t, m.deleted())

	// Second rotation: the previously tracked token id is now revoked.
	second := rotateRoot(t, b, storage)
	require.Empty(t, second.Warnings)
	require.Equal(t, []string{"at-new-user"}, m.deleted())
}

func TestRotateRoot_Organization_NoRevocation(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "organizations", "my-org", "")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	resp := rotateRoot(t, b, storage)

	require.Empty(t, resp.Warnings, "organization tokens are implicitly replaced")
	require.Empty(t, m.deleted(), "organization tokens require no explicit revocation")
	require.Equal(t, tokenOwnerTypeOrganization, resp.Data["token_owner_type"])

	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, "new-org-token", config.Token)
}

func TestRotateRoot_NotConfigured(t *testing.T) {
	b, storage := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
}

func TestRotateRoot_SuccessLeavesNoWAL(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "/api/v2/authentication-tokens/at-old-user")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	resp := rotateRoot(t, b, storage)
	require.Empty(t, resp.Warnings)

	keys, err := framework.ListWAL(context.Background(), storage)
	require.NoError(t, err)
	require.Empty(t, keys, "a fully successful rotation should leave no WAL entries")
}

func TestWALRollback_Committed_RevokesOldToken(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "")

	// The configuration already points at the new token: the rotation
	// committed but the WAL was not cleared (e.g. crash before revoke).
	config := &tfConfig{
		Token:          "new-token",
		Address:        m.server.URL,
		BasePath:       "/api/v2/",
		TokenOwnerType: tokenOwnerTypeUser,
		OwnerID:        "user-abc",
		TokenID:        "at-new-user",
	}
	require.NoError(t, writeConfig(context.Background(), storage, config))

	data := map[string]interface{}{
		"token_owner_type": tokenOwnerTypeUser,
		"owner_id":         "user-abc",
		"old_token_id":     "at-old-user",
		"new_token_id":     "at-new-user",
	}
	err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, rotateRootWALKind, data)
	require.NoError(t, err)
	require.Equal(t, []string{"at-old-user"}, m.deleted(), "committed rotation should revoke the previous token")
}

func TestWALRollback_NotCommitted_DeletesOrphan(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "")

	// The configuration still points at the old token: the new token was
	// created but never committed (crash before persisting config).
	config := &tfConfig{
		Token:          "old-token",
		Address:        m.server.URL,
		BasePath:       "/api/v2/",
		TokenOwnerType: tokenOwnerTypeUser,
		OwnerID:        "user-abc",
		TokenID:        "at-old-user",
	}
	require.NoError(t, writeConfig(context.Background(), storage, config))

	data := map[string]interface{}{
		"token_owner_type": tokenOwnerTypeUser,
		"owner_id":         "user-abc",
		"old_token_id":     "at-old-user",
		"new_token_id":     "at-new-user",
	}
	err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, rotateRootWALKind, data)
	require.NoError(t, err)
	require.Equal(t, []string{"at-new-user"}, m.deleted(), "uncommitted rotation should delete the orphaned new token")
}

func TestWALRollback_UnknownKind(t *testing.T) {
	b, storage := getTestBackend(t)
	err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, "someOtherKind", map[string]interface{}{})
	require.Error(t, err)
}
