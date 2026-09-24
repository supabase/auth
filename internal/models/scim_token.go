package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const (
	SCIMTokenMarker = "scim_"

	scimTokenBytes         = 20
	scimTokenPrefixLength  = len(SCIMTokenMarker) + 7
	scimTokenCreateRetries = 3
)

type SCIMToken struct {
	ID            uuid.UUID  `json:"-" db:"id"`
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

func (t *SCIMToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

func HashSCIMToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateSCIMToken() (string, error) {
	b := make([]byte, scimTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return SCIMTokenMarker + hex.EncodeToString(b), nil
}

func CreateSCIMToken(tx *storage.Connection, provider *SSOProvider, expiresAt *time.Time) (*SCIMToken, string, error) {
	locked := &SSOProvider{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT * FROM %q WHERE id = ? FOR UPDATE", locked.TableName()),
		provider.ID,
	).First(locked); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, "", SSOProviderNotFoundError{}
		}
		return nil, "", errors.Wrap(err, "error locking SSO provider")
	}

	for range scimTokenCreateRetries {
		plaintext, err := generateSCIMToken()
		if err != nil {
			return nil, "", errors.Wrap(err, "error generating SCIM token")
		}

		prefix := plaintext[:scimTokenPrefixLength]
		taken, err := tx.Q().Where("sso_provider_id = ? AND prefix = ?", provider.ID, prefix).Exists(&SCIMToken{})
		if err != nil {
			return nil, "", errors.Wrap(err, "error checking SCIM token prefix")
		}
		if taken {
			continue
		}

		token := &SCIMToken{
			ID:            uuid.Must(uuid.NewV4()),
			SSOProviderID: provider.ID,
			TokenHash:     HashSCIMToken(plaintext),
			Prefix:        prefix,
			ExpiresAt:     expiresAt,
		}
		if err := tx.RawQuery(
			fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, token_hash, prefix, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING *", token.TableName()),
			token.ID, token.SSOProviderID, token.TokenHash, token.Prefix, token.ExpiresAt,
		).First(token); err != nil {
			if isCheckViolation(err, "scim_tokens_expires_at_future") {
				return nil, "", SCIMTokenExpiryError{}
			}
			return nil, "", errors.Wrap(err, "error creating SCIM token")
		}
		return token, plaintext, nil
	}

	return nil, "", errors.New("error creating SCIM token: prefix collision")
}

func FindSCIMTokensBySSOProvider(tx *storage.Connection, providerID uuid.UUID) ([]SCIMToken, error) {
	tokens := []SCIMToken{}
	if err := tx.Q().Where("sso_provider_id = ?", providerID).Order("created_at asc, id asc").All(&tokens); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM tokens")
	}
	return tokens, nil
}

func FindSCIMTokenByPrefix(tx *storage.Connection, providerID uuid.UUID, prefix string) (*SCIMToken, error) {
	tokens := []SCIMToken{}
	if err := tx.Q().Where("sso_provider_id = ? AND prefix = ?", providerID, prefix).Limit(2).All(&tokens); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM token")
	}

	switch len(tokens) {
	case 0:
		return nil, SCIMTokenNotFoundError{}
	case 1:
		return &tokens[0], nil
	default:
		return nil, errors.Errorf("error finding SCIM token: prefix %q is ambiguous", prefix)
	}
}

func (t *SCIMToken) Revoke(tx *storage.Connection) error {
	if t.IsRevoked() {
		return nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET revoked_at = now() WHERE id = ? RETURNING *", t.TableName()),
		t.ID,
	).First(t); err != nil {
		return errors.Wrap(err, "error revoking SCIM token")
	}
	return nil
}

func AuthenticateSCIMToken(tx *storage.Connection, plaintext string) (*SCIMToken, error) {
	token := &SCIMToken{}
	err := tx.RawQuery(
		fmt.Sprintf(`WITH authenticated AS (
  SELECT t.* FROM %[1]q AS t
  JOIN %[2]q AS p ON p.id = t.sso_provider_id
  WHERE (p.disabled IS NULL OR p.disabled = false)
    AND t.token_hash = ?
    AND t.revoked_at IS NULL
    AND (t.expires_at IS NULL OR t.expires_at > now())
), touched AS (
  UPDATE %[1]q AS t SET last_used_at = now()
  FROM authenticated AS a
  WHERE t.id = a.id
    AND (a.last_used_at IS NULL OR a.last_used_at < now() - interval '1 minute')
  RETURNING t.*
)
SELECT * FROM touched
UNION ALL
SELECT * FROM authenticated WHERE NOT EXISTS (SELECT 1 FROM touched)`, token.TableName(), (&SSOProvider{}).TableName()),
		HashSCIMToken(plaintext),
	).First(token)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMTokenNotFoundError{}
		}
		return nil, errors.Wrap(err, "error authenticating SCIM token")
	}
	return token, nil
}
