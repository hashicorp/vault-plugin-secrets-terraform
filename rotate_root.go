// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package tfc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// rotateRootWALKind identifies the write-ahead log entries written during root
// token rotation.
const rotateRootWALKind = "rotateRootToken"

// rotateRootWAL records the non-sensitive identifiers needed to reconcile a
// rotation that was interrupted by a crash or failover. It never stores a token
// value. TFC/E tokens are immutable, so reconciliation always rolls forward:
// the orphaned token (whichever is not the committed one) is deleted; a deleted
// token is never recreated.
type rotateRootWAL struct {
	TokenOwnerType string `json:"token_owner_type"`
	OwnerID        string `json:"owner_id"`
	OldTokenID     string `json:"old_token_id"`
	NewTokenID     string `json:"new_token_id"`
}

// rotateRootToken creates a replacement root token in Terraform Cloud/Enterprise
// and updates the backend configuration to use it. It backs both the manual
// rotate-root endpoint and the automated Rotation Manager callback, so the whole
// operation is serialized by rotationLock to keep a manual rotation from
// interleaving with an automated one.
//
// The order of operations is deliberate: a replacement token is created and
// validated before the configuration is persisted, so a failure before
// persistence leaves the previous token configured and usable. The previous
// token is revoked only after the new token is stored.
func (b *tfBackend) rotateRootToken(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	b.rotationLock.Lock()
	defer b.rotationLock.Unlock()

	// Read the configuration inside the lock so a serialized second caller
	// observes the token committed by the first rotation.
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("the backend is not configured"), nil
	}
	if config.Token == "" {
		return logical.ErrorResponse("the backend is missing a root token; configure one before rotating"), nil
	}

	// Client authenticated with the current root token.
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	// Establish the token owner if it has not been discovered yet.
	if config.TokenOwnerType == "" || config.OwnerID == "" {
		ownerType, ownerID, tokenID, err := client.discoverTokenOwner(ctx)
		if err != nil {
			return nil, err
		}
		config.TokenOwnerType = ownerType
		config.OwnerID = ownerID
		if config.TokenID == "" {
			config.TokenID = tokenID
		}
	}

	// The id of the token being replaced. Empty when Vault has not yet tracked
	// the configured token (e.g. older Terraform Enterprise that does not return
	// the auth-token link). In that case the original token must be revoked
	// manually; every subsequent rotation tracks the id from the create
	// response and revokes automatically.
	oldTokenID := config.TokenID

	// Create the replacement token.
	newToken, err := client.createRootToken(ctx, config.TokenOwnerType, config.OwnerID, explicitMaxTTLExpiry(config.ExplicitMaxTTL))
	if err != nil {
		return nil, fmt.Errorf("error creating new root token: %w", err)
	}

	// Validate the replacement token with its own client before persisting it.
	newTokenClient, err := newClient(&tfConfig{
		Token:    newToken.Token,
		Address:  config.Address,
		BasePath: config.BasePath,
	})
	if err != nil {
		return nil, fmt.Errorf("error building client for new root token: %w", err)
	}
	if err := newTokenClient.validateRootToken(ctx); err != nil {
		return nil, fmt.Errorf("new root token failed validation; the previous token remains configured: %w", err)
	}

	// Persist the new token and rotation metadata.
	config.Token = newToken.Token
	config.TokenID = newToken.ID
	if req.RotationInfo != nil {
		config.SetRotationInfo(req.RotationInfo)
	} else {
		config.SetLastVaultRotation()
	}

	// Record a write-ahead log entry before persisting so a crash between
	// creating the new token and revoking the old one can be reconciled.
	// Organization tokens are implicitly replaced and have nothing to clean up,
	// so they are not logged. The entry stores only identifiers, never a token
	// value.
	var walID string
	if config.TokenOwnerType != tokenOwnerTypeOrganization {
		walID, err = framework.PutWAL(ctx, req.Storage, rotateRootWALKind, &rotateRootWAL{
			TokenOwnerType: config.TokenOwnerType,
			OwnerID:        config.OwnerID,
			OldTokenID:     oldTokenID,
			NewTokenID:     newToken.ID,
		})
		if err != nil {
			return nil, fmt.Errorf("error writing rotation write-ahead log: %w", err)
		}
	}

	if err := writeConfig(ctx, req.Storage, config); err != nil {
		return nil, fmt.Errorf("error saving configuration after creating new root token: %w", err)
	}

	// Reset the cached client so subsequent calls use the new token.
	b.reset()

	// Revoke the previous token. Organization tokens are implicitly replaced by
	// creating a new one and require no explicit revocation. The new token is
	// used for revocation so a compromised previous token is not relied upon.
	var warnings []string
	switch {
	case config.TokenOwnerType == tokenOwnerTypeOrganization:
		// Nothing to revoke and no WAL was written.
	case oldTokenID == "":
		warnings = append(warnings, "the previous root token id is unknown, so it was not revoked automatically; "+
			"revoke the original token manually in Terraform. Subsequent rotations will revoke the previous token automatically.")
		// The rotation committed and there is no previous token to reconcile.
		if w := b.clearRotationWAL(ctx, req, walID); w != "" {
			warnings = append(warnings, w)
		}
	default:
		if err := newTokenClient.revokeRootToken(ctx, config.TokenOwnerType, oldTokenID); err != nil {
			// Leave the WAL in place so walRollback retries the revocation.
			warnings = append(warnings, fmt.Sprintf("the new root token is active and stored, but the previous token (%s) "+
				"could not be revoked and must be revoked manually in Terraform: %s", oldTokenID, err))
		} else if w := b.clearRotationWAL(ctx, req, walID); w != "" {
			warnings = append(warnings, w)
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token_owner_type": config.TokenOwnerType,
			"owner_id":         config.OwnerID,
		},
		Warnings: warnings,
	}
	if !config.LastVaultRotation.IsZero() {
		resp.Data["last_vault_rotation"] = config.LastVaultRotation.UTC()
	}

	return resp, nil
}

// clearRotationWAL deletes a rotation WAL entry once the rotation has fully
// completed. A failure to delete is non-fatal: the leftover entry is reconciled
// by walRollback, so it is returned as a warning rather than an error. An empty
// string means there is nothing to warn about.
func (b *tfBackend) clearRotationWAL(ctx context.Context, req *logical.Request, walID string) string {
	if walID == "" {
		return ""
	}
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return fmt.Sprintf("rotation succeeded but the write-ahead log entry could not be cleared; "+
			"it will be reconciled automatically: %s", err)
	}
	return ""
}

// walRollback reconciles a rotation that was interrupted before its WAL entry
// was cleared. Because TFC/E tokens are immutable, it only rolls forward: it
// deletes whichever token is not the one committed to storage and never
// recreates a token.
func (b *tfBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != rotateRootWALKind {
		return fmt.Errorf("unknown WAL entry kind %q", kind)
	}

	var entry rotateRootWAL
	if err := decodeWAL(data, &entry); err != nil {
		return fmt.Errorf("error decoding rotation write-ahead log: %w", err)
	}

	// Organization tokens are never logged, but guard defensively.
	if entry.TokenOwnerType == tokenOwnerTypeOrganization {
		return nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}
	if config == nil {
		// No configuration to reconcile against; drop the WAL.
		return nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	if config.TokenID == entry.NewTokenID {
		// The rotation committed: the new token is in use. Ensure the previous
		// token is revoked. Idempotent; revoking an empty or already-deleted
		// token is treated as success.
		return client.revokeRootToken(ctx, entry.TokenOwnerType, entry.OldTokenID)
	}

	// The new token was created but never committed (crash before persisting
	// the configuration). The committed configuration still uses the previous
	// token, so delete the orphaned new token. Never recreate a token.
	return client.revokeRootToken(ctx, entry.TokenOwnerType, entry.NewTokenID)
}

// decodeWAL converts the generic WAL payload (decoded from JSON as a map) into
// the typed entry using a JSON round-trip, avoiding an extra dependency.
func decodeWAL(data interface{}, target *rotateRootWAL) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}
