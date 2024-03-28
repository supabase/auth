package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
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
	TokenRefresh
	Anonymous
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
	case TokenRefresh:
		return "token_refresh"
	case Anonymous:
		return "anonymous"
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
	case "token_refresh":
		return TokenRefresh, nil
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

func NewFactor(user *User, friendlyName string, factorType string, state FactorState, secret string) *Factor {
	id := uuid.Must(uuid.NewV4())

	factor := &Factor{
		UserID:       user.ID,
		ID:           id,
		Status:       state.String(),
		FriendlyName: friendlyName,
		Secret:       secret,
		FactorType:   factorType,
	}
	return factor
}

func FindFactorByFactorID(conn *storage.Connection, factorID uuid.UUID) (*Factor, error) {
	var factor Factor
	err := conn.Find(&factor, factorID)
	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, FactorNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &factor, nil
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

func DeleteExpiredFactors(tx *storage.Connection, validityDuration time.Duration) error {
	totalSeconds := int64(validityDuration / time.Second)
	validityInterval := fmt.Sprintf("interval '%d seconds'", totalSeconds)

	factorTable := (&pop.Model{Value: Factor{}}).TableName()
	challengeTable := (&pop.Model{Value: Challenge{}}).TableName()

	query := fmt.Sprintf(`delete from %q where status != 'verified' and not exists (select * from %q where %q.id = %q.factor_id ) and created_at + %s < current_timestamp;`, factorTable, challengeTable, factorTable, challengeTable, validityInterval)
	if err := tx.RawQuery(query).Exec(); err != nil {
		return err
	}
	return nil
}
