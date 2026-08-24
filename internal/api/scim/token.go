package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
)

const TokenPrefix = "scim_"
const tokenLength = 32

func NewSCIMToken() (token, digest string) {
	token = TokenPrefix + crypto.SecureAlphanumeric(tokenLength)
	return token, hashToken(token)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

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

func (t *TokenTenants) touch(ctx context.Context, id string) {
	_ = t.db.WithContext(ctx).RawQuery("UPDATE scim_tokens SET last_used_at = now() WHERE id = ?", id).Exec()
}
