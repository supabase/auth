package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const (
	scimTokenMarker = "scim_"

	scimTokenBytes        = 20
	scimTokenPrefixLength = len(scimTokenMarker) + 7

	activeSCIMTokenClause = "revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())" // #nosec G101
)

type SCIMToken struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	SSOProviderID uuid.UUID  `json:"-" db:"sso_provider_id"`
	TokenHash     string     `json:"-" db:"token_hash"`
	Prefix        string     `json:"prefix" db:"prefix"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at" db:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
	LastUsedAt    *time.Time `json:"last_used_at" db:"last_used_at"`
}

func (SCIMToken) TableName() string {
	return "scim_tokens"
}

func (t *SCIMToken) AfterFind(*pop.Connection) error {
	t.CreatedAt = t.CreatedAt.UTC()
	for _, at := range []*time.Time{t.ExpiresAt, t.RevokedAt, t.LastUsedAt} {
		if at != nil {
			*at = at.UTC()
		}
	}
	return nil
}

func CreateSCIMToken(tx *storage.Connection, providerID uuid.UUID, expiresAt *time.Time) (*SCIMToken, string, error) {
	plaintext := generateSCIMToken()
	token := &SCIMToken{
		ID:            uuid.NewV4(),
		SSOProviderID: providerID,
		TokenHash:     hashSCIMToken(plaintext),
		Prefix:        plaintext[:scimTokenPrefixLength],
		ExpiresAt:     expiresAt,
	}
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, token_hash, prefix, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING *", token.TableName()),
		token.ID, token.SSOProviderID, token.TokenHash, token.Prefix, token.ExpiresAt,
	).First(token); err != nil {
		if utilities.IsCheckViolation(err, "scim_tokens_expires_at_future") {
			return nil, "", ErrSCIMTokenExpiry
		}
		return nil, "", errors.Wrap(err, "error creating SCIM token")
	}
	return token, plaintext, nil
}

func FindSCIMTokensBySSOProvider(tx *storage.Connection, providerID uuid.UUID) ([]SCIMToken, error) {
	tokens := []SCIMToken{}
	if err := tx.Q().Where("sso_provider_id = ?", providerID).Order("created_at asc, id asc").All(&tokens); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM tokens")
	}
	return tokens, nil
}

func FindActiveSCIMTokensBySSOProvider(tx *storage.Connection, providerID uuid.UUID) ([]SCIMToken, error) {
	tokens := []SCIMToken{}
	if err := tx.Q().Where("sso_provider_id = ? AND "+activeSCIMTokenClause, providerID).Order("created_at asc, id asc").All(&tokens); err != nil {
		return nil, errors.Wrap(err, "error finding active SCIM tokens")
	}
	return tokens, nil
}

func RevokeSCIMToken(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMToken, error) {
	token := &SCIMToken{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET revoked_at = COALESCE(revoked_at, now()) WHERE sso_provider_id = ? AND id = ? RETURNING *", token.TableName()),
		providerID, id,
	).First(token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, errors.Wrap(err, "error revoking SCIM token")
	}
	return token, nil
}

func AuthenticateSCIMToken(tx *storage.Connection, plaintext string) (*SCIMToken, error) {
	token := &SCIMToken{}
	if err := tx.RawQuery(
		fmt.Sprintf(`WITH authenticated AS (
  SELECT t.* FROM %[1]q AS t
  JOIN %[2]q AS p ON p.id = t.sso_provider_id
  JOIN %[3]q AS s ON s.sso_provider_id = t.sso_provider_id AND s.enabled
  WHERE (p.disabled IS NULL OR p.disabled = false)
    AND t.token_hash = ?
    AND %[4]s
), touched AS (
  UPDATE %[1]q AS t SET last_used_at = now()
  FROM authenticated AS a
  WHERE t.id = a.id
    AND (a.last_used_at IS NULL OR a.last_used_at < now() - interval '1 minute')
  RETURNING t.*
)
SELECT * FROM touched
UNION ALL
SELECT * FROM authenticated WHERE NOT EXISTS (SELECT 1 FROM touched)`, token.TableName(), SSOProvider{}.TableName(), SCIMSettings{}.TableName(), activeSCIMTokenClause),
		hashSCIMToken(plaintext),
	).First(token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, errors.Wrap(err, "error authenticating SCIM token")
	}
	return token, nil
}

func generateSCIMToken() string {
	b := make([]byte, scimTokenBytes)
	_, _ = rand.Read(b)
	return scimTokenMarker + hex.EncodeToString(b)
}

func hashSCIMToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
