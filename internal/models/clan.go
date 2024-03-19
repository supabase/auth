package models

import (
	"regexp"
	"strings"
	"time"

	"github.com/clanwyse/halo/internal/storage"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gofrs/uuid"
	"github.com/lpar/calendar"
)

type Clan struct {
	ID                      uuid.UUID          `json:"id" db:"id" bun:"id,pk"` //uuid.UUID
	Name                    *string            `json:"name" db:"name"`
	DisplayName             *string            `json:"display_name" db:"display_name"`
	Slug                    *string            `json:"slug" db:"slug"`
	Branding                *JSONMap           `json:"branding" db:"branding"`
	Email                   storage.NullString `json:"email" db:"email"`
	Phone                   *string            `json:"phone" db:"phone"`
	MissionStatement        *string            `json:"mission_statement" db:"mission_statement"`
	MissionStatementSummary *string            `json:"mission_statement_summary" db:"mission_statement_summary"`
	AdditionalTraits        *JSONMap           `json:"additional_traits" db:"additional_traits"`
	DateEstablished         *calendar.Date     `json:"date_established" db:"date_established"`
	CreatedBy               *uuid.UUID         `json:"created_by" db:"created_by"`
	IsPublic                bool               `json:"is_public" db:"is_public"`
	IsBanned                bool               `json:"is_banned" db:"is_banned"`
	SuspendedUntil          *time.Time         `json:"suspended_until" db:"suspended_until"`
	MemberTraitsURL         *string            `json:"member_traits_url" db:"member_traits_url"`
	ClanTypeID              *uuid.UUID         `json:"clan_type_id" db:"clan_type_id"`
	InsertedAt              *time.Time         `json:"inserted_at" db:"inserted_at"`
	UpdatedAt               *time.Time         `json:"updated_at" db:"updated_at"`

	Preferences map[string]interface{} `json:"preferences"`

	Owner       *Profile      `json:"owner" belongs-to:"profiles"`
	ClanType    *ClanType     `json:"clan_type" has_one:"clan_types"`
	ClanMembers *[]ClanMember `json:"clan_members" has_many:"clan_members"`
	ClanGroup   *[]ClanGroup  `json:"clan_group" has_many:"clan_groups"`
}

func (Clan) TableName() string {
	tableName := "clans"
	return tableName
}

func (p Clan) Validate() error {
	return validation.ValidateStruct(&p,
		// Name cannot be empty, and the length must between 3 and 50
		validation.Field(&p.Name, validation.Required, validation.Length(3, 50)),
		// Lastname cannot be empty, and the length must between 3 and 50
		validation.Field(&p.DisplayName, validation.Required, validation.Length(3, 50)),
		// slug cannot be empty
		validation.Field(&p.Slug, validation.Required),
		// email cannot be empty
		validation.Field(&p.Email, validation.Required, validation.Match(
			regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"))),
	)
}

func NewClan(name, display_name, email, slug string, ct uuid.UUID, user User) (*Clan, error) {

	id := uuid.Must(uuid.NewV4())
	clan := &Clan{
		ID:          id,
		Name:        &name,
		DisplayName: &display_name,
		Slug:        &slug,
		ClanTypeID:  &ct,
		CreatedBy:   &user.ID,
		Email:       storage.NullString(strings.ToLower(email)),
	}
	return clan, nil
}

// GetEmail returns the user's email as a string
func (i *Clan) GetEmail() string {
	return string(i.Email)
}

// NewClan returns an Clan associated to the user's id.
func FindClanByID(tx *storage.Connection, id *uuid.UUID) (*Clan, error) {

	clan := &Clan{
		CreatedBy: id,
	}

	return clan, nil
}
