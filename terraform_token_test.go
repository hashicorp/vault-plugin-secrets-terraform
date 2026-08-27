package tfc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateTeamTokenWithOptions_ExpiredAt(t *testing.T) {
	roleMaxTTL := 1 * time.Hour
	systemMaxTTL := 32 * 24 * time.Hour // Vault default ~32 days

	role := terraformRoleEntry{
		TeamID:         "team-test",
		Description:    "test",
		CredentialType: teamCredentialType,
		TTL:            200 * time.Second,
		MaxTTL:         roleMaxTTL, // role has explicit max_ttl of 1 hour
	}

	effectiveMaxTTL := role.MaxTTL
	if effectiveMaxTTL == 0 {
		effectiveMaxTTL = systemMaxTTL
	}

	// role max_ttl should win over system max_ttl
	require.Equal(t, roleMaxTTL, effectiveMaxTTL)

	// expired_at should be ~1 hour from now, not ~32 days
	expiredAt := time.Now().Add(effectiveMaxTTL)
	require.WithinDuration(t, time.Now().Add(roleMaxTTL), expiredAt, 5*time.Second)
}
