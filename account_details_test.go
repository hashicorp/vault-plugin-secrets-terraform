// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveTokenIdentity(t *testing.T) {
	tests := []struct {
		name           string
		responseCode   int
		responseBody   string
		wantTokenType  string
		wantID         string
		wantErrContain string
	}{
		{
			name:         "organization token - simple name",
			responseCode: http.StatusOK,
			responseBody: `{
				"data": {
					"id": "user-abc123",
					"type": "users",
					"attributes": { "username": "api-org-mullen-14JAXvyITM" },
					"relationships": {}
				}
			}`,
			wantTokenType: "organization",
			wantID:        "mullen",
		},
		{
			name:         "organization token - hyphenated name",
			responseCode: http.StatusOK,
			responseBody: `{
				"data": {
					"id": "user-abc123",
					"type": "users",
					"attributes": { "username": "api-org-my-cool-org-14JAXvyITM" },
					"relationships": {}
				}
			}`,
			wantTokenType: "organization",
			wantID:        "my-cool-org",
		},
		{
			name:         "team token",
			responseCode: http.StatusOK,
			responseBody: `{
				"data": {
					"id": "user-xyz",
					"type": "users",
					"attributes": { "username": "api-team-myteam-abc123" },
					"relationships": {
						"authenticated-resource": {
							"data": { "id": "team-RGhi7xU4NWWmp1MQ", "type": "teams" }
						}
					}
				}
			}`,
			wantTokenType: "team",
			wantID:        "team-RGhi7xU4NWWmp1MQ",
		},
		{
			name:         "user token",
			responseCode: http.StatusOK,
			responseBody: `{
				"data": {
					"id": "user-V3R563qtqNzY6fA1",
					"type": "users",
					"attributes": { "username": "drew-mullen" },
					"relationships": {}
				}
			}`,
			wantTokenType: "user",
			wantID:        "user-V3R563qtqNzY6fA1",
		},
		{
			name:           "team token - missing relationship",
			responseCode:   http.StatusOK,
			responseBody:   `{"data":{"id":"user-x","type":"users","attributes":{"username":"api-team-foo-bar"},"relationships":{}}}`,
			wantErrContain: "authenticated-resource ID is missing",
		},
		{
			name:           "org token - username too short",
			responseCode:   http.StatusOK,
			responseBody:   `{"data":{"id":"user-x","type":"users","attributes":{"username":"api-org-x"},"relationships":{}}}`,
			wantErrContain: "unexpected organization token username format",
		},
		{
			name:           "unauthorized",
			responseCode:   http.StatusUnauthorized,
			responseBody:   `{"errors":["unauthorized"]}`,
			wantErrContain: "status 401",
		},
		{
			name:           "bad json",
			responseCode:   http.StatusOK,
			responseBody:   `not json`,
			wantErrContain: "error decoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v2/account/details", r.URL.Path)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				w.WriteHeader(tt.responseCode)
				fmt.Fprint(w, tt.responseBody)
			}))
			defer srv.Close()

			tokenType, id, err := resolveTokenIdentity(
				context.Background(),
				srv.URL,
				"/api/v2/",
				"test-token",
			)

			if tt.wantErrContain != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantTokenType, tokenType)
			assert.Equal(t, tt.wantID, id)
		})
	}
}
