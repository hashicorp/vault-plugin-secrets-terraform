// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// accountDetailsResponse represents the JSON response from the TFC/TFE
// account/details API endpoint.
type accountDetailsResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Username string `json:"username"`
		} `json:"attributes"`
		Relationships struct {
			AuthenticatedResource struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"authenticated-resource"`
		} `json:"relationships"`
	} `json:"data"`
}

// resolveTokenIdentity calls the TFC/TFE account/details API to determine
// the token type (organization, team, or user) and the associated entity ID.
//
// Organization tokens have usernames starting with "api-org-". The org name
// is extracted by splitting on "-" and dropping the first two and last parts.
//
// Team tokens have usernames starting with "api-team-". The team ID is
// taken from the authenticated-resource relationship.
//
// All other tokens are treated as user tokens, using data.id directly.
func resolveTokenIdentity(ctx context.Context, address, basePath, token string) (tokenType string, id string, err error) {
	url := strings.TrimRight(address, "/") + "/" + strings.Trim(basePath, "/") + "/account/details"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("error creating account details request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error calling account/details: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("account/details returned status %d", resp.StatusCode)
	}

	var details accountDetailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return "", "", fmt.Errorf("error decoding account/details response: %w", err)
	}

	username := details.Data.Attributes.Username

	if strings.HasPrefix(username, "api-org-") {
		// Organization token: extract org name from username.
		// Username format: "api-org-<orgname>-<random>"
		// Organization names can contain "-", so we split on "-" and drop
		// the first two parts ("api", "org") and the last part (random suffix).
		parts := strings.Split(username, "-")
		if len(parts) < 4 {
			return "", "", fmt.Errorf("unexpected organization token username format: %s", username)
		}
		orgName := strings.Join(parts[2:len(parts)-1], "-")
		return "organization", orgName, nil
	}

	if strings.HasPrefix(username, "api-team-") {
		// Team token: get team ID from the authenticated-resource relationship.
		teamID := details.Data.Relationships.AuthenticatedResource.Data.ID
		if teamID == "" {
			return "", "", fmt.Errorf("team token detected but authenticated-resource ID is missing")
		}
		return "team", teamID, nil
	}

	// User token: use the user ID directly.
	return "user", details.Data.ID, nil
}
