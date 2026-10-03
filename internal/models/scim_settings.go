package models

import (
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMSettings struct {
	SSOProviderID uuid.UUID `db:"sso_provider_id"`
	Enabled       bool      `db:"enabled"`
}

func (SCIMSettings) TableName() string {
	return "scim_settings"
}

func EnableSCIM(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	count, err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %[1]q (sso_provider_id, enabled) VALUES (?, true) ON CONFLICT (sso_provider_id) DO UPDATE SET enabled = true, updated_at = now() WHERE %[1]q.enabled = false", SCIMSettings{}.TableName()),
		providerID,
	).ExecWithCount()
	return count > 0, errors.Wrap(err, "error enabling SCIM")
}

func DisableSCIM(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET enabled = false, updated_at = now() WHERE sso_provider_id = ? AND enabled", SCIMSettings{}.TableName()),
		providerID,
	).ExecWithCount()
	return count > 0, errors.Wrap(err, "error disabling SCIM")
}

func IsSCIMEnabled(tx *storage.Connection, providerID uuid.UUID) (bool, error) {
	enabled, err := tx.Q().Where("sso_provider_id = ? AND enabled", providerID).Exists(&SCIMSettings{})
	if err != nil {
		return false, errors.Wrap(err, "error finding SCIM settings")
	}
	return enabled, nil
}
