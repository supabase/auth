package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
)

// TokenPrefix marks a SCIM token, so that one is recognisable in a log or a
// support ticket and so that another kind of bearer token can be turned away
// without a query.
const TokenPrefix = "scim_"

// tokenLength is the randomness in a token: 32 base32 characters is 160 bits.
// That is the reason hashToken needs no salt.
const tokenLength = 32

// NewSCIMToken mints a token for a provider. It returns the token, which exists
// only in this process and only now, and the digest to store.
//
// There is no admin API for this yet. A token is installed by hand:
//
//	insert into auth.scim_tokens (sso_provider_id, token_hash)
//	values ('<provider id>', '<digest>');
func NewSCIMToken() (token, digest string) {
	token = TokenPrefix + crypto.SecureAlphanumeric(tokenLength)
	return token, hashToken(token)
}

// hashToken is SHA-256 with no salt, deliberately. A token holds 160 bits of
// randomness, so there is no dictionary to defend it against, and an unsalted
// digest is one a query can be indexed on -- which is what makes the digest the
// lookup key rather than something to verify after finding a candidate row.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenTenants resolves a bearer token to the SSO provider it provisions.
type TokenTenants struct {
	db *storage.Connection
}

func NewTokenTenants(db *storage.Connection) *TokenTenants {
	return &TokenTenants{db: db}
}

type scimTokenRow struct {
	ID            string `db:"id"`
	SSOProviderID string `db:"sso_provider_id"`
}

func (t *TokenTenants) Lookup(ctx context.Context, credential string) (string, error) {
	// A credential that is not one of ours cannot be in the table, so it is
	// turned away without a query. This also keeps an admin JWT out of the log
	// line a failed lookup would write.
	if !strings.HasPrefix(credential, TokenPrefix) {
		return "", ErrNotFound
	}

	var rows []scimTokenRow
	err := t.db.WithContext(ctx).RawQuery(
		"SELECT t.id, t.sso_provider_id FROM scim_tokens t"+
			" JOIN sso_providers p ON p.id = t.sso_provider_id"+
			" WHERE t.token_hash = ?"+
			"   AND t.revoked_at IS NULL"+
			"   AND (t.expires_at IS NULL OR t.expires_at > now())"+
			"   AND (p.disabled IS NULL OR p.disabled = false)",
		hashToken(credential),
	).All(&rows)
	if err != nil {
		return "", fmt.Errorf("scim: looking up token: %w", err)
	}

	if len(rows) == 0 {
		return "", ErrNotFound
	}

	t.touch(ctx, rows[0].ID)
	return rows[0].SSOProviderID, nil
}

// touch records that a token was used. It is best effort: a request that was
// authorised does not stop being authorised because this write failed.
func (t *TokenTenants) touch(ctx context.Context, id string) {
	err := t.db.WithContext(ctx).RawQuery(
		"UPDATE scim_tokens SET last_used_at = now() WHERE id = ?", id,
	).Exec()
	if err != nil {
		logrus.WithError(err).Warn("scim: recording SCIM token use")
	}
}
