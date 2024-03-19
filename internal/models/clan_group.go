package models

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gofrs/uuid"
)

type ClanGroup struct {
	ID         *uuid.UUID `json:"id" db:"id" bun:"id,pk"` //uuid.UUID
	Name       *string    `json:"name" db:"name"`
	ClanID     *uuid.UUID `json:"clan_id" db:"clan_id"`
	InsertedAt *time.Time `json:"inserted_at" db:"inserted_at"`
	UpdatedAt  *time.Time `json:"updated_at" db:"updated_at"`

	Clan Clan `json:"clan" belongs_to:"clan"`
}

func (ClanGroup) TableName() string {
	tableName := "clan_groups"
	return tableName
}

func (p ClanGroup) Validate() error {
	return validation.ValidateStruct(&p,
		// Name cannot be empty, and the length must between 3 and 50
		validation.Field(&p.Name, validation.Required, validation.Length(3, 50)),
	)
}
