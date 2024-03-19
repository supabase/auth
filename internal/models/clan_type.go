package models

import (
	"database/sql"
	"time"

	"github.com/clanwyse/halo/internal/storage"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

type ClanType struct {
	ID          *uuid.UUID `json:"id" db:"id" bun:"id,pk"` //uuid.UUID
	ClanType    *string    `json:"type" db:"clan_type_type"`
	Description *string    `json:"description" db:"description"`
	RefCode     *string    `json:"ref_code" db:"ref_code"`
	InsertedAt  *time.Time `json:"inserted_at" db:"inserted_at"`
	UpdatedAt   *time.Time `json:"updated_at" db:"updated_at"`

	Clan Clan `json:"clan" belongs_to:"clan"`
}

func (ClanType) TableName() string {
	tableName := "clan_types"
	return tableName
}

// NewClanType returns all clan types in the database
func FindAllClanTypes(tx storage.Connection) ([]*ClanType, error) {
	var clantype []*ClanType
	if err := tx.All(&clantype); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	return clantype, nil
}
