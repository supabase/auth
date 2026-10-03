package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMUser struct {
	ID            uuid.UUID  `db:"id"`
	SSOProviderID uuid.UUID  `db:"sso_provider_id"`
	UserID        *uuid.UUID `db:"user_id"`
	Resource      []byte     `db:"resource"`
	UserName      string     `db:"user_name"`
	ExternalID    *string    `db:"external_id"`
	Active        bool       `db:"active"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at"`
}

func (SCIMUser) TableName() string {
	return "scim_users"
}

type SCIMIdentityRename struct {
	UserID   uuid.UUID
	Provider string
	From     string
	To       string
	Data     map[string]any
}

type SCIMIdentityEmailChange struct {
	UserID   uuid.UUID
	Provider string
	Subject  string
	Email    string
}

var scimUsersTable = scimTable{
	tableName:  SCIMUser{}.TableName(),
	label:      "SCIM user",
	columns:    "id, sso_provider_id, user_id, resource, user_name, external_id, active, created_at, updated_at, deleted_at",
	nameColumn: "user_name",
	scope:      "sso_provider_id = ? AND deleted_at IS NULL",
	conflict:   ErrSCIMUserConflict,
}

func CreateSCIMUser(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMUser, error) {
	return createSCIMRow[SCIMUser](tx, scimUsersTable, providerID, resource)
}

func FindSCIMUser(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMRow[SCIMUser](tx, scimUsersTable, SCIMTarget{ProviderID: providerID, ID: id})
}

func ReplaceSCIMUserIfChanged(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMUser, bool, error) {
	return replaceSCIMRowIfChanged[SCIMUser](tx, scimUsersTable, target, resource)
}

func FindSCIMUsers(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMUser, int, error) {
	return findSCIMPage[SCIMUser](tx, scimUsersTable, providerID, query)
}

func ReplaceSCIMUser(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMUser, error) {
	return replaceSCIMRow[SCIMUser](tx, scimUsersTable, target, resource)
}

func DeleteSCIMUser(tx *storage.Connection, target SCIMTarget) (*SCIMUser, error) {
	return writeSCIMRow[SCIMUser](tx, scimUsersTable, target, scimWrite{verb: "deleting", sql: "UPDATE %q SET deleted_at = now(), updated_at = clock_timestamp()"})
}

func SoftDeleteSCIMUsersByUserID(tx *storage.Connection, userID uuid.UUID) ([]SCIMUser, error) {
	rows := []SCIMUser{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = clock_timestamp() WHERE user_id = ? AND deleted_at IS NULL RETURNING %s", scimUsersTable.tableName, scimUsersTable.columns),
		userID,
	).All(&rows); err != nil {
		return nil, errors.Wrap(err, "error deleting SCIM users by user id")
	}
	return rows, nil
}

func LinkSCIMUser(tx *storage.Connection, user *SCIMUser, userID uuid.UUID) error {
	deleted, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NOT NULL", user.SSOProviderID, userID).Exists(&SCIMUser{})
	if err != nil {
		return errors.Wrap(err, "error finding deleted SCIM user")
	}
	if deleted {
		return ErrSCIMUserDeleted
	}
	return LinkNewSCIMUser(tx, user, userID)
}

func LinkNewSCIMUser(tx *storage.Connection, user *SCIMUser, userID uuid.UUID) error {
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET user_id = ?, updated_at = clock_timestamp() WHERE id = ? RETURNING %s", scimUsersTable.tableName, scimUsersTable.columns),
		userID, user.ID,
	).First(user)
	if isUniqueViolation(err) {
		return ErrSCIMUserLinked
	}
	return errors.Wrap(err, "error linking SCIM user")
}

func IsSCIMManaged(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	managed, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NULL", providerID, userID).Exists(&SCIMUser{})
	if err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return managed, nil
}

func IsSCIMUserDeprovisionedByProvider(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	return isSCIMUserDeprovisioned(tx, "sso_provider_id = ? AND user_id = ?", providerID, userID)
}

func IsSCIMUserDeprovisioned(tx *storage.Connection, userID uuid.UUID) (bool, error) {
	return isSCIMUserDeprovisioned(tx, "user_id = ?", userID)
}

func RenameSCIMIdentity(tx *storage.Connection, rename SCIMIdentityRename) error {
	encoded, err := json.Marshal(rename.Data)
	if err != nil {
		return errors.Wrap(err, "error encoding identity data")
	}
	table := Identity{}.TableName()
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %[1]q WHERE user_id = ? AND provider = ? AND provider_id <> ? AND (lower(provider_id) = lower(?) OR provider_id = ?) AND EXISTS (SELECT 1 FROM %[1]q WHERE user_id = ? AND provider = ? AND provider_id = ?)", table),
		rename.UserID, rename.Provider, rename.From, rename.From, rename.To, rename.UserID, rename.Provider, rename.From,
	).Exec(); err != nil {
		return errors.Wrap(err, "error removing stale SCIM identities")
	}
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET provider_id = ?, identity_data = identity_data || ?::jsonb, updated_at = now() WHERE user_id = ? AND provider = ? AND provider_id = ?", table),
		rename.To, string(encoded), rename.UserID, rename.Provider, rename.From,
	).ExecWithCount()
	if err != nil {
		if isUniqueViolation(err) {
			return ErrSCIMUserConflict
		}
		return errors.Wrap(err, "error renaming SCIM identity")
	}
	if count == 0 {
		return SCIMNotFoundError{}
	}
	return nil
}

func ChangeSCIMIdentityEmail(tx *storage.Connection, change SCIMIdentityEmailChange) error {
	taken, err := tx.Q().Where("provider = ? AND email = lower(?) AND user_id <> ?", change.Provider, change.Email, change.UserID).Exists(&Identity{})
	if err != nil {
		return errors.Wrap(err, "error finding SCIM identity email")
	}
	if taken {
		return ErrSCIMUserConflict
	}
	return errors.Wrap(tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET identity_data = identity_data || jsonb_build_object('email', ?::text), updated_at = now() WHERE user_id = ? AND provider = ? AND provider_id = ?", Identity{}.TableName()),
		change.Email, change.UserID, change.Provider, change.Subject,
	).Exec(), "error changing SCIM identity email")
}

func isSCIMUserDeprovisioned(tx *storage.Connection, where string, args ...any) (bool, error) {
	result := struct {
		Deprovisioned bool `db:"deprovisioned"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT coalesce(bool_and(deleted_at IS NOT NULL OR NOT active), false) AS deprovisioned FROM %q WHERE %s", scimUsersTable.tableName, where),
		args...,
	).First(&result); err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return result.Deprovisioned, nil
}
