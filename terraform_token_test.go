// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-tfe"
	"github.com/stretchr/testify/require"
)

// teamTokenMock is a minimal HTTP server that records the expired-at value
// sent by createTeamTokenWithOptions so we can assert it without a real TFC account.
type teamTokenMock struct {
	server     *httptest.Server
	expiredAt  string // raw value from the JSON:API request body
}

func newTeamTokenMock(t *testing.T, teamID string) *teamTokenMock {
	t.Helper()
	m := &teamTokenMock{}

	mux := http.NewServeMux()

	// go-tfe calls /ping when constructing a client
	mux.HandleFunc("/api/v2/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// team token create endpoint — record the request body and return a minimal response
	mux.HandleFunc("/api/v2/teams/"+teamID+"/authentication-tokens", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// extract the value of "expired-at" from the JSON:API request body.
		// body looks like: {"data":{"attributes":{"expired-at":"2026-...Z",...}}}
		const key = `"expired-at":"`
		if idx := strings.Index(bodyStr, key); idx != -1 {
			rest := bodyStr[idx+len(key):]
			if end := strings.Index(rest, `"`); end != -1 {
				m.expiredAt = rest[:end]
			}
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, `{"data":{"id":"at-test","type":"authentication-tokens","attributes":{`+
			`"token":"test-token","description":"test","created-at":"2020-01-01T00:00:00Z",`+
			`"expired-at":"2020-01-01T00:00:00Z","last-used-at":"2020-01-01T00:00:00Z"}}}`)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// TestCreateTeamTokenWithOptions_ExpiredAt calls createTeamTokenWithOptions
// directly and asserts the expired-at sent to the TFC API uses the role's
// max_ttl, not the (much larger) system max TTL.
//
// Regression test for VAULT-38815.
func TestCreateTeamTokenWithOptions_ExpiredAt(t *testing.T) {
	teamID := "team-test"
	roleMaxTTL := 1 * time.Hour
	systemMaxTTL := 32 * 24 * time.Hour // Vault default ~32 days

	m := newTeamTokenMock(t, teamID)

	cfg, err := tfe.NewClient(&tfe.Config{
		Address:  m.server.URL,
		BasePath: "/api/v2/",
		Token:    "test-token",
	})
	require.NoError(t, err)

	c := &client{cfg}

	role := terraformRoleEntry{
		TeamID:         teamID,
		Description:    "test",
		CredentialType: teamCredentialType,
		TTL:            200 * time.Second,
		MaxTTL:         roleMaxTTL, // role has explicit max_ttl of 1 hour
	}

	before := time.Now()
	_, err = createTeamTokenWithOptions(context.Background(), c, role, systemMaxTTL)
	require.NoError(t, err)

	// The expired-at recorded by the mock must be ~1 hour from now, not ~32 days.
	// If the old max() bug were present, expiredAt would be ~32 days in the future.
	require.NotEmpty(t, m.expiredAt, "expected expired-at to be sent in the request")

	expiredAt, err := time.Parse(time.RFC3339, m.expiredAt)
	require.NoError(t, err)

	// must be close to now + roleMaxTTL (1 hour)
	require.WithinDuration(t, before.Add(roleMaxTTL), expiredAt, 10*time.Second,
		"expired_at should be ~1 hour from now (role max_ttl), not ~32 days (system max TTL)")

	// must NOT be close to now + systemMaxTTL (32 days)
	require.False(t, expiredAt.After(before.Add(2*time.Hour)),
		"expired_at %v is too far in the future — system max TTL leaked into the TFC token expiry", expiredAt)
}
