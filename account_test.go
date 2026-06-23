// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAuthTokenID(t *testing.T) {
	cases := map[string]struct {
		link     string
		expected string
	}{
		"empty":             {link: "", expected: ""},
		"full path":         {link: "/api/v2/authentication-tokens/at-a7B29xYqL5mP0wK1", expected: "at-a7B29xYqL5mP0wK1"},
		"id only":           {link: "at-a7B29xYqL5mP0wK1", expected: "at-a7B29xYqL5mP0wK1"},
		"surrounding space": {link: "  /api/v2/authentication-tokens/at-123  ", expected: "at-123"},
		"non token link":    {link: "/api/v2/users/user-123", expected: ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, parseAuthTokenID(tc.link))
		})
	}
}

func TestOwnerFromAccountDetails(t *testing.T) {
	t.Run("organization", func(t *testing.T) {
		details := accountDetailsFromJSON(t, `{
			"data": {
				"relationships": {
					"authenticated-resource": {
						"data": {"id": "mullen", "type": "organizations"}
					}
				}
			}
		}`)

		ownerType, ownerID, tokenID, err := ownerFromAccountDetails(details)
		require.NoError(t, err)
		require.Equal(t, tokenOwnerTypeOrganization, ownerType)
		require.Equal(t, "mullen", ownerID)
		require.Empty(t, tokenID)
	})

	t.Run("team", func(t *testing.T) {
		details := accountDetailsFromJSON(t, `{
			"data": {
				"relationships": {
					"authenticated-resource": {
						"data": {"id": "team-o6DCATiUbPqTs4Es", "type": "teams"}
					}
				}
			}
		}`)

		ownerType, ownerID, _, err := ownerFromAccountDetails(details)
		require.NoError(t, err)
		require.Equal(t, tokenOwnerTypeTeam, ownerType)
		require.Equal(t, "team-o6DCATiUbPqTs4Es", ownerID)
	})

	t.Run("user with auth-token link", func(t *testing.T) {
		details := accountDetailsFromJSON(t, `{
			"data": {
				"relationships": {
					"authenticated-resource": {
						"data": {"id": "user-V3R563qtJNcExAkN", "type": "users"}
					}
				},
				"links": {
					"self": "/api/v2/users/user-V3R563qtJNcExAkN",
					"auth-token": "/api/v2/authentication-tokens/at-a7B29xYqL5mP0wK1"
				}
			}
		}`)

		ownerType, ownerID, tokenID, err := ownerFromAccountDetails(details)
		require.NoError(t, err)
		require.Equal(t, tokenOwnerTypeUser, ownerType)
		require.Equal(t, "user-V3R563qtJNcExAkN", ownerID)
		require.Equal(t, "at-a7B29xYqL5mP0wK1", tokenID)
	})

	t.Run("missing authenticated resource", func(t *testing.T) {
		details := accountDetailsFromJSON(t, `{"data": {}}`)

		_, _, _, err := ownerFromAccountDetails(details)
		require.Error(t, err)
	})

	t.Run("unsupported resource type", func(t *testing.T) {
		details := accountDetailsFromJSON(t, `{
			"data": {
				"relationships": {
					"authenticated-resource": {
						"data": {"id": "ws-123", "type": "workspaces"}
					}
				}
			}
		}`)

		_, _, _, err := ownerFromAccountDetails(details)
		require.Error(t, err)
	})

	t.Run("nil details", func(t *testing.T) {
		_, _, _, err := ownerFromAccountDetails(nil)
		require.Error(t, err)
	})
}

func accountDetailsFromJSON(t *testing.T, raw string) *accountDetails {
	t.Helper()

	details := new(accountDetails)
	require.NoError(t, json.Unmarshal([]byte(raw), details))
	return details
}
