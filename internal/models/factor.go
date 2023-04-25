package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
)

type FactorState int

const (
	FactorStateUnverified FactorState = iota
	FactorStateVerified
)

func (factorState FactorState) String() string {
	switch factorState {
	case FactorStateUnverified:
		return "unverified"
	case FactorStateVerified:
		return "verified"
	}
	return ""
}

const TOTP = "totp"

type AuthenticationMethod int

const (
	OAuth AuthenticationMethod = iota
	PasswordGrant
	OTP
	TOTPSignIn
	SSOSAML
	Recovery
	Invite
	MagicLink
	EmailSignup
	EmailChange
)

func (authMethod AuthenticationMethod) String() string {
	switch authMethod {
	case OAuth:
		return "oauth"
	case PasswordGrant:
		return "password"
	case OTP:
		return "otp"
	case TOTPSignIn:
		return "totp"
	case Recovery:
		return "recovery"
	case Invite:
		return "invite"
	case SSOSAML:
		return "sso/saml"
	case MagicLink:
		return "magiclink"
	case EmailSignup:
		return "email/signup"
	case EmailChange:
		return "email_change"
	}
	return ""
}

func ParseAuthenticationMethod(authMethod string) (AuthenticationMethod, error) {
	if strings.HasSuffix(authMethod, "signup") {
		authMethod = "email/signup"
	}
	switch authMethod {
	case "oauth":
		return OAuth, nil
	case "password":
		return PasswordGrant, nil
	case "otp":
		return OTP, nil
	case "totp":
		return TOTPSignIn, nil
	case "recovery":
		return Recovery, nil
	case "invite":
		return Invite, nil
	case "sso/saml":
		return SSOSAML, nil
	case "magiclink":
		return MagicLink, nil
	case "email/signup":
		return EmailSignup, nil
	case "email_change":
		return EmailChange, nil
	}
	return 0, fmt.Errorf("unsupported authentication method %q", authMethod)
}

type Factor struct {
	ID           uuid.UUID   `json:"id" db:"id"`
	User         User        `json:"-" belongs_to:"user"`
	UserID       uuid.UUID   `json:"-" db:"user_id"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
	Status       string      `json:"status" db:"status"`
	FriendlyName string      `json:"friendly_name,omitempty" db:"friendly_name"`
	Secret       string      `json:"-" db:"secret"`
	FactorType   string      `json:"factor_type" db:"factor_type"`
	Challenge    []Challenge `json:"-" has_many:"challenges"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, friendlyName string, factorType string, state FactorState, secret string) (*Factor, error) {
	id := uuid.Must(uuid.NewV4())

	factor := &Factor{
		UserID:       user.ID,
		ID:           id,
		Status:       state.String(),
		FriendlyName: friendlyName,
		Secret:       secret,
		FactorType:   factorType,
	}
	return factor, nil
}

// FindFactorsByUser returns all factors belonging to a user ordered by timestamp
func FindFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ?", user.ID).Order("created_at asc").All(&factors); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return factors, nil
		}
		return nil, errors.Wrap(err, "Database error when finding MFA factors associated to user")
	}
	return factors, nil
}

func FindFactorByFactorID(tx *storage.Connection, factorID uuid.UUID) (*Factor, error) {
	factor, err := findFactor(tx, "id = ?", factorID)
	if err != nil {
		return nil, FactorNotFoundError{}
	}
	return factor, nil
}

func findFactor(tx *storage.Connection, query string, args ...interface{}) (*Factor, error) {
	obj := &Factor{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FactorNotFoundError{}
		}
		return nil, errors.Wrap(err, "Database error finding factor")
	}

	return obj, nil
}

func DeleteUnverifiedFactors(tx *storage.Connection, user *User) error {
	if err := tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Factor{}}).TableName()+" WHERE user_id = ? and status = ?", user.ID, FactorStateUnverified.String()).Exec(); err != nil {
		return err
	}

	return nil
}

// UpdateFriendlyName changes the friendly name
func (f *Factor) UpdateFriendlyName(tx *storage.Connection, friendlyName string) error {
	f.FriendlyName = friendlyName
	return tx.UpdateOnly(f, "friendly_name", "updated_at")
}

// UpdateStatus modifies the factor status
func (f *Factor) UpdateStatus(tx *storage.Connection, state FactorState) error {
	f.Status = state.String()
	return tx.UpdateOnly(f, "status", "updated_at")
}

// UpdateFactorType modifies the factor type
func (f *Factor) UpdateFactorType(tx *storage.Connection, factorType string) error {
	f.FactorType = factorType
	return tx.UpdateOnly(f, "factor_type", "updated_at")
}

func (f *Factor) DowngradeSessionsToAAL1(tx *storage.Connection) error {
	sessions, err := FindSessionsByFactorID(tx, f.ID)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := tx.RawQuery("DELETE FROM "+(&pop.Model{Value: AMRClaim{}}).TableName()+" WHERE session_id = ? AND authentication_method = ?", session.ID, f.FactorType).Exec(); err != nil {
			return err
		}
	}
	return updateFactorAssociatedSessions(tx, f.UserID, f.ID, AAL1.String())
}

func (f *Factor) IsOwnedBy(user *User) bool {
	return f.UserID == user.ID
}

func (f *Factor) IsVerified() bool {
	return f.Status == FactorStateVerified.String()
}

func DeleteFactorsByUserId(tx *storage.Connection, userId uuid.UUID) error {
	if err := tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Factor{}}).TableName()+" WHERE user_id = ?", userId).Exec(); err != nil {
		return err
	}
	return nil
}
