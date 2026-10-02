package models

import (
	"encoding/json"
	"fmt"
	"slices"
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

const scimUserColumns = "id, sso_provider_id, user_id, resource, user_name, external_id, active, created_at, updated_at, deleted_at"

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
	columns:    scimUserColumns,
	nameColumn: "user_name",
	liveClause: "deleted_at IS NULL",
	notFound:   SCIMUserNotFoundError{},
	stale:      SCIMStaleError{},
	conflict:   SCIMUserConflictError{},
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
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = clock_timestamp() WHERE %s AND "+scimVersionClause+" RETURNING %s", scimUsersTable.tableName, scimUsersTable.targetClause(), scimUsersTable.columns),
		target.ID, target.ProviderID, target.UpdatedAt, target.UpdatedAt,
	).First(user)
	if err != nil {
		return nil, scimUsersTable.writeError(tx, target, err, "deleting")
	}
	return user, nil
}

func SoftDeleteSCIMUsersByUserID(tx *storage.Connection, userID uuid.UUID) ([]SCIMUser, error) {
	rows := []SCIMUser{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = clock_timestamp() WHERE user_id = ? AND deleted_at IS NULL RETURNING "+scimUserColumns, scimUsersTable.tableName),
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
		return SCIMUserDeletedError{}
	}
	return LinkNewSCIMUser(tx, user, userID)
}

func LinkNewSCIMUser(tx *storage.Connection, user *SCIMUser, userID uuid.UUID) error {
	updated := struct {
		UpdatedAt time.Time `db:"updated_at"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET user_id = ?, updated_at = clock_timestamp() WHERE id = ? RETURNING updated_at", scimUsersTable.tableName),
		userID, user.ID,
	).First(&updated); err != nil {
		if isUniqueViolation(err) {
			return SCIMUserLinkedError{}
		}
		return errors.Wrap(err, "error linking SCIM user")
	}
	user.UserID = &userID
	user.UpdatedAt = updated.UpdatedAt
	return nil
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
			return SCIMUserConflictError{}
		}
		return errors.Wrap(err, "error renaming SCIM identity")
	}
	if count == 0 {
		return SCIMIdentityNotFoundError{}
	}
	return nil
}

func ChangeSCIMIdentityEmail(tx *storage.Connection, change SCIMIdentityEmailChange) error {
	table := Identity{}.TableName()
	taken := struct {
		Exists bool `db:"exists"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %q WHERE provider = ? AND email = lower(?) AND user_id <> ?) AS exists", table),
		change.Provider, change.Email, change.UserID,
	).First(&taken); err != nil {
		return errors.Wrap(err, "error finding SCIM identity email")
	}
	if taken.Exists {
		return SCIMUserConflictError{}
	}
	encoded, err := json.Marshal(map[string]any{"email": change.Email})
	if err != nil {
		return errors.Wrap(err, "error encoding identity data")
	}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET identity_data = identity_data || ?::jsonb, updated_at = now() WHERE user_id = ? AND provider = ? AND provider_id = ?", table),
		string(encoded), change.UserID, change.Provider, change.Subject,
	).Exec(); err != nil {
		return errors.Wrap(err, "error changing SCIM identity email")
	}
	return nil
}

func isSCIMUserDeprovisioned(tx *storage.Connection, where string, args ...any) (bool, error) {
	result := struct {
		AnyRow bool `db:"any_row"`
		Live   bool `db:"live"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf(
			"SELECT EXISTS(SELECT 1 FROM %[1]q WHERE %[2]s) AS any_row, "+
				"EXISTS(SELECT 1 FROM %[1]q WHERE %[2]s AND deleted_at IS NULL AND active) AS live",
			scimUsersTable.tableName, where,
		),
		append(slices.Clone(args), args...)...,
	).First(&result); err != nil {
		return false, errors.Wrap(err, "error finding SCIM user")
	}
	return result.AnyRow && !result.Live, nil
}
