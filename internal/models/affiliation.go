package models

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/gofrs/uuid"
)

// clans can have only 1 direct parent
type ClanAffiliation struct {
	ID           uuid.UUID  `json:"id" db:"id" bun:"id,pk"` //uuid.UUID
	ClanID       *uuid.UUID `json:"clan_id" db:"clan_id"`
	RelatedTo    *uuid.UUID `json:"related_to" db:"related_to"`
	Relationship string     `json:"relationship" db:"relationship"`
	InsertedAt   *time.Time `json:"inserted_at" db:"inserted_at"`
	UpdatedAt    *time.Time `json:"updated_at" db:"updated_at"`
}

func (ClanAffiliation) TableName() string {
	tableName := "clan_affiliations"
	return tableName
}

func (p ClanAffiliation) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.ID, validation.Required, validation.Length(3, 50), is.UUID),
		validation.Field(&p.Relationship, validation.Required, validation.Length(3, 50)),
	)
}
