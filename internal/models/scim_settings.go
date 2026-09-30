package models

import (
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMSettings struct {
	SSOProviderID uuid.UUID `json:"-" db:"sso_provider_id"`
	Enabled       bool      `json:"enabled" db:"enabled"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

func (SCIMSettings) TableName() string {
	return "scim_settings"
}

func (s *SCIMSettings) AfterFind(*pop.Connection) error {
	s.CreatedAt = s.CreatedAt.UTC()
	s.UpdatedAt = s.UpdatedAt.UTC()
	return nil
}

func EnableSCIM(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	table := SCIMSettings{}.TableName()
	rows := []SCIMSettings{}
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %[1]q (sso_provider_id, enabled) VALUES (?, true) ON CONFLICT (sso_provider_id) DO UPDATE SET enabled = true, updated_at = now() WHERE %[1]q.enabled = false RETURNING *", table),
		providerID,
	).All(&rows); err != nil {
		return false, errors.Wrap(err, "error enabling SCIM")
	}
	return len(rows) > 0, nil
}

func DisableSCIM(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	rows := []SCIMSettings{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET enabled = false, updated_at = now() WHERE sso_provider_id = ? AND enabled RETURNING *", SCIMSettings{}.TableName()),
		providerID,
	).All(&rows); err != nil {
		return false, errors.Wrap(err, "error disabling SCIM")
	}
	return len(rows) > 0, nil
}

func IsSCIMEnabled(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	enabled, err := tx.Q().Where("sso_provider_id = ? AND enabled", providerID).Exists(&SCIMSettings{})
	if err != nil {
		return false, errors.Wrap(err, "error finding SCIM settings")
	}
	return enabled, nil
}
