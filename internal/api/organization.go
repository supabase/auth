package api

import (
	"database/sql"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

func findOrganization(tx *storage.Connection, query string, args ...interface{}) (uuid.UUID, error) {

	org := struct {
		ID uuid.UUID `db:"id"`
	}{}

	if err := tx.RawQuery(query, args...).First(&org); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return uuid.Nil, OrganizationNotFoundError{}
		}

		return uuid.Nil, errors.Wrap(err, "error finding organization")
	}

	return org.ID, nil
}

// Find the organization ID by the project ID and which admin user is associated with it(email)
func findAdminOrganizationIDByEmailAndProjectID(tx *storage.Connection, email string, project_id uuid.UUID) (uuid.UUID, error) {
	// Find all the users_id with the email and then find the organization_id with the project_id and admin_id
	query := `
		SELECT o.id
		FROM organizations o
		JOIN users u ON o.admin_id = u.id
		WHERE u.email = $1 AND o.project_id = $2
	`
	return findOrganization(tx, query, email, project_id)
}
