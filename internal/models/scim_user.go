package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
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

type SCIMUserFilter struct {
	UserName   *string
	ExternalID *string
}

func (f SCIMUserFilter) where(providerID uuid.UUID) (string, []any) {
	clauses := []string{"sso_provider_id = ?", "deleted_at IS NULL"}
	args := []any{providerID}
	if f.UserName != nil {
		clauses = append(clauses, "user_name = lower(?)")
		args = append(args, *f.UserName)
	}
	if f.ExternalID != nil {
		clauses = append(clauses, "external_id = ?")
		args = append(args, *f.ExternalID)
	}
	return strings.Join(clauses, " AND "), args
}

func CreateSCIMUser(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource) VALUES (?, ?, ?::jsonb) RETURNING "+scimUserColumns, user.TableName()),
		uuid.Must(uuid.NewV4()), providerID, string(resource),
	).First(user)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, SCIMUserConflictError{}
		}
		return nil, errors.Wrap(err, "error creating SCIM user")
	}
	return user, nil
}

func FindSCIMUser(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMUser(tx, providerID, id, "")
}

func FindSCIMUserForUpdate(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	return findSCIMUser(tx, providerID, id, " FOR UPDATE")
}

func findSCIMUser(tx *storage.Connection, providerID, id uuid.UUID, lock string) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT "+scimUserColumns+" FROM %q WHERE id = ? AND sso_provider_id = ? AND deleted_at IS NULL"+lock, user.TableName()),
		id, providerID,
	).First(user)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMUserNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM user")
	}
	return user, nil
}

func FindSCIMUsers(tx *storage.Connection, providerID uuid.UUID, filter SCIMUserFilter, offset, limit int) ([]SCIMUser, int, error) {
	where, args := filter.where(providerID)

	rows := []struct {
		SCIMUser
		Total int `db:"total"`
	}{}
	if limit > 0 {
		err := tx.RawQuery(
			fmt.Sprintf("SELECT "+scimUserColumns+", count(*) OVER () AS total FROM %q WHERE %s ORDER BY created_at ASC, id ASC OFFSET ? LIMIT ?", (&SCIMUser{}).TableName(), where),
			append(args, offset, limit)...,
		).All(&rows)
		if err != nil {
			return nil, 0, errors.Wrap(err, "error finding SCIM users")
		}
	}
	if len(rows) == 0 {
		total, err := tx.Q().Where(where, args...).Count(&SCIMUser{})
		if err != nil {
			return nil, 0, errors.Wrap(err, "error counting SCIM users")
		}
		return []SCIMUser{}, total, nil
	}

	users := make([]SCIMUser, len(rows))
	for i := range rows {
		users[i] = rows[i].SCIMUser
	}
	return users, rows[0].Total, nil
}

func ReplaceSCIMUser(tx *storage.Connection, providerID, id uuid.UUID, resource []byte, updatedAt *time.Time) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND deleted_at IS NULL AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimUserColumns, user.TableName()),
		string(resource), id, providerID, updatedAt, updatedAt,
	).First(user)
	if err != nil {
		switch {
		case errors.Cause(err) == sql.ErrNoRows && updatedAt != nil:
			if _, findErr := FindSCIMUser(tx, providerID, id); findErr != nil {
				return nil, findErr
			}
			return nil, SCIMUserStaleError{}
		case errors.Cause(err) == sql.ErrNoRows:
			return nil, SCIMUserNotFoundError{}
		case isUniqueViolation(err):
			return nil, SCIMUserConflictError{}
		}
		return nil, errors.Wrap(err, "error replacing SCIM user")
	}
	return user, nil
}

func DeleteSCIMUser(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMUser, error) {
	user := &SCIMUser{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now(), updated_at = now() WHERE id = ? AND sso_provider_id = ? AND deleted_at IS NULL RETURNING "+scimUserColumns, user.TableName()),
		id, providerID,
	).First(user)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMUserNotFoundError{}
		}
		return nil, errors.Wrap(err, "error deleting SCIM user")
	}
	return user, nil
}

func LinkSCIMUser(tx *storage.Connection, user *SCIMUser, userID uuid.UUID) error {
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ? FOR UPDATE", (&User{}).TableName()),
		userID,
	).Exec(); err != nil {
		return errors.Wrap(err, "error locking user")
	}

	linked, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NULL", user.SSOProviderID, userID).Exists(&SCIMUser{})
	if err != nil {
		return errors.Wrap(err, "error finding linked SCIM user")
	}
	if linked {
		return SCIMUserLinkedError{}
	}

	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET user_id = ? WHERE id = ?", user.TableName()),
		userID, user.ID,
	).Exec(); err != nil {
		return errors.Wrap(err, "error linking SCIM user")
	}
	user.UserID = &userID
	return nil
}

func HasDeletedSCIMUser(tx *storage.Connection, providerID, userID uuid.UUID) (bool, error) {
	deleted, err := tx.Q().Where("sso_provider_id = ? AND user_id = ? AND deleted_at IS NOT NULL", providerID, userID).Exists(&SCIMUser{})
	if err != nil {
		return false, errors.Wrap(err, "error finding deleted SCIM user")
	}
	return deleted, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}

func isCheckViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.CheckViolation && pgErr.ConstraintName == constraint
}
