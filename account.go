// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Token owner types as stored on the backend configuration and returned on
// reads. They identify which Terraform Cloud/Enterprise token API is used to
// rotate the configured root token.
const (
	tokenOwnerTypeOrganization = "organization"
	tokenOwnerTypeTeam         = "team"
	tokenOwnerTypeUser         = "user"
)

// accountDetails models the subset of the Terraform Cloud/Enterprise
// /account/details JSON:API response that Vault needs to discover the owner of
// the configured root token.
type accountDetails struct {
	Data struct {
		Relationships struct {
			AuthenticatedResource struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"authenticated-resource"`
		} `json:"relationships"`
		Links struct {
			// AuthToken is the link to the token that authenticated the
			// request, e.g. "/api/v2/authentication-tokens/at-xxxxxxxx". It is
			// only returned by newer versions of Terraform Enterprise and HCP
			// Terraform.
			AuthToken string `json:"auth-token"`
		} `json:"links"`
	} `json:"data"`
}

// readAccountDetails calls the Terraform Cloud/Enterprise /account/details
// endpoint using the configured root token and returns the parsed document.
//
// The typed go-tfe Users.ReadCurrent helper does not expose the
// authenticated-resource relationship or the auth-token link, so the response
// is decoded directly from the JSON:API document.
func (c *client) readAccountDetails(ctx context.Context) (*accountDetails, error) {
	req, err := c.NewRequest("GET", "account/details", nil)
	if err != nil {
		return nil, err
	}

	details := new(accountDetails)
	if err := req.DoJSON(ctx, details); err != nil {
		return nil, err
	}

	return details, nil
}

// discoverTokenOwner queries Terraform Cloud/Enterprise for the identity of the
// configured root token and returns the normalized owner type, owner id, and
// (when available) the token id used for revocation.
//
// tokenID is empty on versions of Terraform Enterprise that do not yet return
// the auth-token link. In that case the caller must establish the token id by
// performing a rotation and persisting the id of the token it creates.
func (c *client) discoverTokenOwner(ctx context.Context) (ownerType, ownerID, tokenID string, err error) {
	details, err := c.readAccountDetails(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("error reading account details: %w", err)
	}

	return ownerFromAccountDetails(details)
}

// ownerFromAccountDetails maps a parsed /account/details document to Vault's
// normalized owner type, owner id, and token id. It is separated from the
// network call so the mapping can be unit tested.
func ownerFromAccountDetails(details *accountDetails) (ownerType, ownerID, tokenID string, err error) {
	if details == nil {
		return "", "", "", errors.New("nil account details")
	}

	resource := details.Data.Relationships.AuthenticatedResource.Data

	switch resource.Type {
	case "organizations":
		ownerType = tokenOwnerTypeOrganization
	case "teams":
		ownerType = tokenOwnerTypeTeam
	case "users":
		ownerType = tokenOwnerTypeUser
	case "":
		return "", "", "", errors.New("Terraform did not return an authenticated resource for the configured token")
	default:
		return "", "", "", fmt.Errorf("unsupported token owner type %q returned by Terraform", resource.Type)
	}

	ownerID = resource.ID
	if ownerID == "" {
		return "", "", "", errors.New("Terraform did not return an owner id for the configured token")
	}

	tokenID = parseAuthTokenID(details.Data.Links.AuthToken)

	return ownerType, ownerID, tokenID, nil
}

// parseAuthTokenID extracts the token id (e.g. "at-xxxxxxxx") from the
// auth-token link returned by /account/details. It returns an empty string when
// the link is absent (older Terraform Enterprise) or does not reference a token.
func parseAuthTokenID(link string) string {
	if link == "" {
		return ""
	}

	id := path.Base(strings.TrimSpace(link))
	if !strings.HasPrefix(id, "at-") {
		return ""
	}

	return id
}
