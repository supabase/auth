package models

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/lpar/calendar"
)

type ClanMember struct {
	ID               *uuid.UUID     `json:"id" db:"id" bun:"id,pk"`
	ProfileID        *uuid.UUID     `json:"profile_id" db:"profile_id"`
	ClanID           *uuid.UUID     `json:"clan_id" db:"clan_id"`
	DateJoined       *calendar.Date `json:"date_joined" db:"date_joined"` //date
	AdditionalTraits JSONMap        `json:"additional_traits" db:"additional_traits"`
	IsBanned         bool           `json:"is_banned" db:"is_banned"`
	Tags             []uuid.UUID    `json:"tags" db:"tags"`
	SuspendedUntil   *time.Time     `json:"suspended_until" db:"suspended_until"`
	InsertedAt       *time.Time     `json:"inserted_at" db:"inserted_at"`
	UpdatedAt        *time.Time     `json:"updated_at" db:"updated_at"`

	// Profile Profile `json:"profile" bun:"rel:belongs-to"`
	Clan Clan `json:"clan" belongs_to:"clan"`
}

func (ClanMember) TableName() string {
	tableName := "clan_members"
	return tableName
}
