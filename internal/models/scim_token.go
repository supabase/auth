package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/gofrs/uuid"

	"github.com/supabase/auth/internal/crypto"
)

const SCIMTokenPrefix = "scim_"
const scimTokenLength = 32

type SCIMToken struct {
	ID uuid.UUID `db:"id"`

	SSOProvider   *SSOProvider `belongs_to:"sso_providers"`
	SSOProviderID uuid.UUID    `db:"sso_provider_id"`

	TokenHash  string     `db:"token_hash"`
	Prefix     string     `db:"prefix"`
	CreatedAt  time.Time  `db:"created_at"`
	ExpiresAt  *time.Time `db:"expires_at"`
	RevokedAt  *time.Time `db:"revoked_at"`
	LastUsedAt *time.Time `db:"last_used_at"`
}

func (SCIMToken) TableName() string {
	return "scim_tokens"
}

func NewSCIMToken(provider *SSOProvider) (*SCIMToken, string) {
	token, digest := NewSCIMBearerToken()
	return &SCIMToken{
		ID:            uuid.Must(uuid.NewV4()),
		SSOProviderID: provider.ID,
		SSOProvider:   provider,
		TokenHash:     digest,
		Prefix:        token[8:],
	}, token
}

func NewSCIMBearerToken() (token, digest string) {
	token = SCIMTokenPrefix + crypto.SecureAlphanumeric(scimTokenLength)
	return token, ToSCIMHash(token)
}

func ToSCIMHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
