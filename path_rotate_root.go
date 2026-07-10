// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRoot(b *tfBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTerraformCloud,
			OperationVerb:   "rotate",
			OperationSuffix: "root",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathRotateRootHelpSyn,
		HelpDescription: pathRotateRootHelpDesc,
	}
}

func (b *tfBackend) pathRotateRootUpdate(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return b.rotateRootToken(ctx, req)
}

const pathRotateRootHelpSyn = `
Request to rotate the root token used by Vault to access Terraform Cloud or Enterprise.
`

const pathRotateRootHelpDesc = `
This path rotates the root token configured at the "config" endpoint. Vault
creates a new token of the same type (organization, team, or user) in Terraform
Cloud or Enterprise, validates it, stores it as the new root token, and revokes
the previous token where Terraform supports revocation.

This endpoint can be used for on-demand rotation and does not require Vault
Enterprise. Scheduled, automatic rotation is configured with the rotation fields
on the "config" endpoint and requires Vault Enterprise.
`
