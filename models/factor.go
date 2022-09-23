package models

import (
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

const FactorUnverifiedState = "unverified"
const FactorVerifiedState = "verified"

type AuthenticationMethod int

const (
	OAuth AuthenticationMethod = iota
	OAuthIDGrant
	PasswordGrant
	AutoConfirmSignup
	EmailVerification
	SMSOrEmailOTP
	TOTP
)

func (authMethod AuthenticationMethod) String() string {
	switch authMethod {
	case OAuth:
		return "oauth"
	case OAuthIDGrant:
		return "oauth_id"
	case PasswordGrant:
		return "password"
	case AutoConfirmSignup:
		return "autoconfirm"
	case EmailVerification:
		return "email_verification"
	case SMSOrEmailOTP:
		return "sms_or_email_otp"
	case TOTP:
		return "TOTP"
	default:
		return ""
	}
}

type Factor struct {
	ID           uuid.UUID `json:"id" db:"id"`
	User         User      `json:"-" belongs_to:"user"`
	UserID       uuid.UUID `json:"-" db:"user_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	Status       string    `json:"status" db:"status"`
	FriendlyName string    `json:"friendly_name,omitempty" db:"friendly_name"`
	TOTPSecret   string    `json:"-" db:"totp_secret"`
	FactorType   string    `json:"factor_type" db:"factor_type"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, friendlyName, factorType, status, totpSecret string) (*Factor, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	factor := &Factor{
		UserID:       user.ID,
		ID:           id,
		Status:       status,
		FriendlyName: friendlyName,
		TOTPSecret:   totpSecret,
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
		return nil, errors.Wrap(err, "Error finding mfa factors")
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

func FindFactorByFriendlyName(tx *storage.Connection, friendlyName string) (*Factor, error) {
	factor, err := findFactor(tx, "friendly_name = ?", friendlyName)
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
		return nil, errors.Wrap(err, "error finding factor")
	}

	return obj, nil
}

func FindVerifiedFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ? AND status = ?", user.ID, FactorVerifiedState).All(&factors); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return factors, nil
		}
		return nil, errors.Wrap(err, "Error finding verified mfa factors")
	}
	return factors, nil
}

// Change the friendly name
func (f *Factor) UpdateFriendlyName(tx *storage.Connection, friendlyName string) error {
	f.FriendlyName = friendlyName
	return tx.UpdateOnly(f, "friendly_name", "updated_at")
}

// Change the factor status
func (f *Factor) UpdateStatus(tx *storage.Connection, status string) error {
	f.Status = status
	return tx.UpdateOnly(f, "status", "updated_at")
}

// Checks if MFA is Enabled
func IsMFAEnabled(tx *storage.Connection, user *User) (bool, error) {
	factors, err := FindVerifiedFactorsByUser(tx, user)
	if err != nil {
		return false, err
	}
	if len(factors) >= 1 {
		return true, nil
	}
	return false, nil
}

// Change the factor type
func (f *Factor) UpdateFactorType(tx *storage.Connection, factorType string) error {
	f.FactorType = factorType
	return tx.UpdateOnly(f, "factor_type", "updated_at")
}

func (f *Factor) DowngradeSessionsToAAL1(tx *storage.Connection) error {
	return updateFactorAssociatedSessions(tx, f.UserID, f.ID, AAL1.String())

}
