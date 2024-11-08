package models

import (
	"database/sql"
	"time"

	"auth/internal/storage"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

type Organization struct {
	ID              uuid.UUID `json:"id" db:"id"`
	ProjectID       uuid.UUID `json:"project_id" db:"project_id"`
	AdminID         uuid.UUID `json:"admin_id" db:"admin_id"`
	Name            string    `json:"name" db:"name"`
	AdminTierModel  string    `json:"admin_tier_model" db:"admin_tier_model"`
	ClientTierModel string    `json:"client_tier_model" db:"client_tier_model"`
	AdminTierTime   string    `json:"admin_tier_time" db:"admin_tier_time"`
	ClientTierTime  string    `json:"client_tier_time" db:"client_tier_time"`
	AdminTierUsage  string    `json:"admin_tier_usage" db:"admin_tier_usage"`
	ClientTierUsage string    `json:"client_tier_usage" db:"client_tier_usage"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

func findOrganization(tx *storage.Connection, query string, args ...interface{}) (*Organization, error) {
	obj := &Organization{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OrganizationNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding organization")
	}

	return obj, nil
}

func FindTiersByOrganizationIDAndOrganizationRole(tx *storage.Connection, organization_id uuid.UUID, organization_role string) (string, string, string, error) {

	var tier_model string
	var tier_time string
	var tier_usage string
	var query string
	var args []interface{}

	if organization_id != uuid.Nil {
		query = "id = ?"
		args = append(args, organization_id)
		organization, err := findOrganization(tx, query, args...)

		if err != nil {
			return "", "", "", err
		}

		if organization_role == "admin" {
			tier_model = organization.AdminTierModel
			tier_time = organization.AdminTierTime
			tier_usage = organization.AdminTierUsage
		} else {
			tier_model = organization.ClientTierModel
			tier_time = organization.ClientTierTime
			tier_usage = organization.ClientTierUsage
		}
	}
	return tier_model, tier_time, tier_usage, nil
}
