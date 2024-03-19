package models

import (
	"database/sql"
	"regexp"
	"time"

	"github.com/clanwyse/halo/internal/storage"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/gofrs/uuid"
	"github.com/lpar/calendar"
	"github.com/pkg/errors"
)

type Profile struct {
	ID             *uuid.UUID     `json:"id" db:"id" bun:"id,pk"`
	FirstName      *string        `json:"first_name" db:"first_name"`
	LastName       *string        `json:"last_name" db:"last_name"`
	Username       *string        `json:"username" db:"username"`
	Email          string         `json:"email" db:"email"`
	Phone          *string        `json:"phone" db:"phone"`
	PhotoURI       *string        `json:"photo_uri" db:"photo_uri"`
	Bio            *string        `json:"bio" db:"bio"`
	BirthDate      *calendar.Date `json:"birth_date" db:"birth_date"` // date without time and timezone
	IsBanned       *bool          `json:"is_banned" db:"is_banned"`
	SuspendedUntil *time.Time     `json:"suspended_until" db:"suspended_until"`
	IdentityID     uuid.UUID      `json:"identity_id" db:"identity_id"`
	InsertedAt     *time.Time     `json:"inserted_at" db:"inserted_at"`
	UpdatedAt      *time.Time     `json:"updated_at" db:"updated_at"`

	Preference map[string]interface{} `json:"preferences,omitempty"`
	Clan       *[]Clan                `json:"clan" has_many:"clans"`
	// ClanMembers        *[]ClanMember      `json:"clan_members" bun:"rel:belongs-to"`

}

func (Profile) TableName() string {
	tableName := "profiles"
	return tableName
}

func (p Profile) Validate() error {
	return validation.ValidateStruct(&p,
		// Firstname cannot be empty, and the length must between 3 and 50
		validation.Field(&p.FirstName, validation.Required, validation.Length(3, 50)),
		// Lastname cannot be empty, and the length must between 3 and 50
		validation.Field(&p.LastName, validation.Required, validation.Length(3, 50)),
		// username cannot be empty
		validation.Field(&p.Username, validation.Required),
		validation.Field(&p.IdentityID, validation.Required, is.UUID),
		// email cannot be empty
		validation.Field(&p.Email, validation.Required, validation.Match(
			regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"))),
	)
}

// UpdateLastSignInAt update field last_sign_in_at for user according to specified field
func (p *Profile) UpdateFirstName(tx *storage.Connection, n *string) error {
	p.FirstName = n
	return tx.UpdateOnly(p, "first_name")
}

func (p *Profile) UpdateLastName(tx *storage.Connection, n *string) error {
	p.LastName = n
	return tx.UpdateOnly(p, "last_name")
}

func (p *Profile) UpdateUsername(tx *storage.Connection, n *string) error {
	p.Username = n
	return tx.UpdateOnly(p, "username")
}

func (p *Profile) UpdateDOB(tx *storage.Connection, n *calendar.Date) error {
	p.BirthDate = n
	return tx.UpdateOnly(p, "birth_date")
}

func (p *Profile) UpdateBio(tx *storage.Connection, n *string) error {
	p.Bio = n
	return tx.UpdateOnly(p, "bio")
}

func findProfile(tx *storage.Connection, query string, args ...interface{}) (*Profile, error) {
	obj := &Profile{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, ProfileNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding profile")
	}

	return obj, nil
}

func FindProfileByID(tx *storage.Connection, id uuid.UUID) (*Profile, error) {
	return findProfile(tx, "id = ?", uuid.Nil, id)
}
