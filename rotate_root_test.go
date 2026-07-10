// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"io"
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

	mu            sync.Mutex
	deletedIDs    []string
	createdPath   string
	createdBodies []string

	// uniqueTokens makes every create return a distinct token id/value
	// (at-new-<type>-N). This is required to reason about orphaned tokens across
	// many rotations; the default fixed-id behavior is kept for existing tests.
	uniqueTokens bool
	createCount  int
	// liveTokens tracks tokens created via the create endpoint that have not yet
	// been deleted. It is the set used to detect orphans.
	liveTokens map[string]bool
}

func newMockTFE(t *testing.T, resourceType, ownerID, authTokenLink string) *mockTFE {
	t.Helper()

	m := &mockTFE{
		resourceType:  resourceType,
		ownerID:       ownerID,
		authTokenLink: authTokenLink,
		liveTokens:    make(map[string]bool),
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
			body, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			id, token := newID, newToken
			if m.uniqueTokens {
				m.createCount++
				id = fmt.Sprintf("%s-%d", newID, m.createCount)
				token = fmt.Sprintf("%s-%d", newToken, m.createCount)
			}
			m.createdPath = r.URL.Path
			m.createdBodies = append(m.createdBodies, string(body))
			m.liveTokens[id] = true
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/vnd.api+json")
			fmt.Fprint(w, tokenJSONAPI(id, token, rootTokenDescription))
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
		delete(m.liveTokens, id)
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

// createBodies returns the raw request bodies of every token-create call.
func (m *mockTFE) createBodies() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.createdBodies...)
}

// liveCreatedTokens returns the ids of tokens created via the create endpoint
// that have not been deleted. Any such token that is not the one referenced by
// the stored config is an orphan.
func (m *mockTFE) liveCreatedTokens() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.liveTokens))
	for id := range m.liveTokens {
		out = append(out, id)
	}
	return out
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

func TestRotateRoot_Team_UniqueDescriptionAndRevoke(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "teams", "team-abc", "/api/v2/authentication-tokens/at-old-team")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	resp := rotateRoot(t, b, storage)

	require.Empty(t, resp.Warnings, "team token id was known, so no secret-zero warning expected")
	require.Equal(t, tokenOwnerTypeTeam, resp.Data["token_owner_type"])
	require.Equal(t, "team-abc", resp.Data["owner_id"])

	// The previous team token is revoked by id.
	require.Equal(t, []string{"at-old-team"}, m.deleted())

	// Terraform requires team token descriptions to be unique per team, and the
	// replacement is created before the old one is deleted. The create request
	// must therefore carry the description prefix plus a unique suffix, never the
	// bare constant.
	bodies := m.createBodies()
	require.Len(t, bodies, 1)
	require.Contains(t, bodies[0], rootTokenDescription+"(",
		"team token description must include a unique suffix")

	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.Equal(t, "new-team-token", config.Token)
	require.Equal(t, "at-new-team", config.TokenID)
	require.Equal(t, tokenOwnerTypeTeam, config.TokenOwnerType)
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

// TestRotateRoot_ConcurrentConfigOps_NoRaceOrTear exercises rotation, config
// writes, and config reads concurrently to verify they are serialized by
// rotationLock. Run under -race, it guards against a regression where a config
// write and a rotation interleave their read-modify-write of the config entry,
// leaving config.Token out of sync with config.TokenID (torn state) or losing
// an update entirely.
func TestRotateRoot_ConcurrentConfigOps_NoRaceOrTear(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "/api/v2/authentication-tokens/at-old-user")
	writeRotationTestConfig(t, b, storage, m.server.URL)

	const iterations = 50
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(3)

		// Concurrent rotation.
		go func() {
			defer wg.Done()
			_, _ = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "rotate-root",
				Storage:   storage,
			})
		}()

		// Concurrent config write (token-only update).
		go func() {
			defer wg.Done()
			_, _ = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Data: map[string]interface{}{
					"token": "secret-zero-token",
				},
				Storage: storage,
			})
		}()

		// Concurrent config read.
		go func() {
			defer wg.Done()
			_, _ = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			})
		}()
	}
	wg.Wait()

	// After all concurrent operations settle, the persisted config must be
	// internally consistent: Token and TokenID must belong to the same token.
	// Each handler builds a complete config under the exclusive lock, so the
	// stored pair is always one produced by a single operation, never a mix of
	// one operation's Token with another's TokenID.
	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotEmpty(t, config.Token, "config.Token must not be empty after concurrent ops")
	require.NotEmpty(t, config.TokenID, "config.TokenID must not be empty after concurrent ops")

	// The only two consistent (Token, TokenID) pairs the mock can produce:
	//   - rotation:     ("new-user-token", "at-new-user")
	//   - config write: ("secret-zero-token", "at-old-user")  [owner re-discovered]
	validPairs := map[string]string{
		"new-user-token":    "at-new-user",
		"secret-zero-token": "at-old-user",
	}
	wantID, ok := validPairs[config.Token]
	require.True(t, ok, "config.Token has an unexpected value: %q", config.Token)
	require.Equal(t, wantID, config.TokenID,
		"config.Token %q and config.TokenID %q are mismatched (torn write)", config.Token, config.TokenID)
	require.Equal(t, tokenOwnerTypeUser, config.TokenOwnerType)
	require.Equal(t, "user-abc", config.OwnerID)
}

// TestRotateRoot_ConcurrentRotations_NoOrphans is the strong crash/concurrency
// invariant for rotationLock. It fires many rotations concurrently (simulating a
// manual rotate-root racing the automated Rotation Manager callback) and asserts
// that no orphaned tokens are left behind in Terraform: every token created must
// either be revoked or be the single token the committed config now points to.
//
// Without the lock this fails: two rotations read the same previous token id,
// both create a replacement, both persist (last writer wins), and both revoke
// the same previous token, leaving the other replacement created-but-never-
// revoked, i.e. orphaned. The lock serializes rotations so each revokes exactly
// the token the prior one created.
func TestRotateRoot_ConcurrentRotations_NoOrphans(t *testing.T) {
	b, storage := getTestBackend(t)
	m := newMockTFE(t, "users", "user-abc", "/api/v2/authentication-tokens/at-old-user")
	m.uniqueTokens = true
	writeRotationTestConfig(t, b, storage, m.server.URL)

	const rotations = 30
	var wg sync.WaitGroup
	wg.Add(rotations)
	for i := 0; i < rotations; i++ {
		go func() {
			defer wg.Done()
			_, _ = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "rotate-root",
				Storage:   storage,
			})
		}()
	}
	wg.Wait()

	config, err := getConfig(context.Background(), storage)
	require.NoError(t, err)
	require.NotEmpty(t, config.TokenID)

	// The only token that may remain live in Terraform is the one the committed
	// config references. Anything else is an orphan created by an interleaved
	// rotation whose replacement was never revoked.
	live := m.liveCreatedTokens()
	require.ElementsMatch(t, []string{config.TokenID}, live,
		"expected exactly the committed token to remain live; extra entries are orphaned tokens")
}
