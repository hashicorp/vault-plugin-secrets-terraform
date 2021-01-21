package tfc

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-tfe"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	terraformTokenType = "terraform_token"
)

func isOrgToken(organization string, team string) bool {
	return organization != "" && team == ""
}

func isTeamToken(team string) bool {
	return team != ""
}

func createOrgToken(ctx context.Context, c *client, organization string) (*terraformToken, error) {
	if _, err := c.Organizations.Read(ctx, organization); err != nil {
		return nil, err
	}

	token, err := c.OrganizationTokens.Generate(ctx, organization)
	if err != nil {
		return nil, err
	}

	tfToken := &terraformToken{}
	tfToken.translateOrganizationToken(token)
	return tfToken, nil
}

func createTeamToken(ctx context.Context, c *client, teamID string) (*terraformToken, error) {
	if _, err := c.Teams.Read(ctx, teamID); err != nil {
		return nil, err
	}

	token, err := c.TeamTokens.Generate(ctx, teamID)
	if err != nil {
		return nil, err
	}

	tfToken := &terraformToken{}
	tfToken.translateTeamToken(token)
	return tfToken, nil
}

func createUserToken(ctx context.Context, c *client, userID string) (*terraformToken, error) {
	// TODO: user-supplied description
	token, err := c.UserTokens.Generate(ctx, userID, tfe.UserTokenGenerateOptions{})
	if err != nil {
		return nil, err
	}

	tfToken := &terraformToken{}
	tfToken.translateUserToken(token)
	return tfToken, nil
}

func (b *tfBackend) terraformTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error getting client: {{err}}", err)
	}

	teamID := ""
	teamIDRaw, ok := req.Secret.InternalData["team_id"]
	if ok {
		teamID, ok = teamIDRaw.(string)
		if !ok {
			return nil, fmt.Errorf("secret is missing team_id internal data")
		}

	}

	organization := ""
	organizationRaw, ok := req.Secret.InternalData["organization"]
	if ok {
		organization, ok = organizationRaw.(string)
		if !ok {
			return nil, fmt.Errorf("secret is missing organization internal data")
		}
	}

	if isOrgToken(organization, teamID) {
		// revoke org API token
		if err := client.OrganizationTokens.Delete(ctx, organization); err != nil {
			return nil, errwrap.Wrapf("error revoking organization token: {{err}}", err)
		}
		return nil, nil
	}
	if isTeamToken(teamID) {
		// revoke team API token
		if err := client.TeamTokens.Delete(ctx, teamID); err != nil {
			return nil, errwrap.Wrapf("error revoking team token: {{err}}", err)
		}
		return nil, nil
	}

	tokenID := ""
	tokenIDRaw, ok := req.Secret.InternalData["token_id"]
	if ok {
		tokenID, ok = tokenIDRaw.(string)
		if !ok {
			return nil, fmt.Errorf("secret is missing tokenID internal data")
		}
	}

	if err := client.UserTokens.Delete(ctx, tokenID); err != nil {
		return nil, errwrap.Wrapf("error revoking user token: {{err}}", err)
	}
	return nil, nil
}

func (b *tfBackend) terraformTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token id internal data")
	}

	//get the credential entry
	role := roleRaw.(string)
	cred, err := b.credentialRead(ctx, req.Storage, role)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}

	if cred == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if cred.TTL > 0 {
		resp.Secret.TTL = cred.MaxTTL
	}
	if cred.MaxTTL > 0 {
		resp.Secret.MaxTTL = cred.MaxTTL
	}

	return resp, nil
}
