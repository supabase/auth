package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/crypto"
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
const Phone = "phone"

type AuthenticationMethod int

const (
	OAuth AuthenticationMethod = iota
	PasswordGrant
	OTP
	TOTPSignIn
	MFAPhone
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
	case MFAPhone:
		return "mfa/phone"
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
	case "mfa/sms":
		return MFAPhone, nil
	}
	return 0, fmt.Errorf("unsupported authentication method %q", authMethod)
}

type Factor struct {
	ID uuid.UUID `json:"id" db:"id"`
	// TODO: Consider removing this nested user field. We don't use it.
	User             User               `json:"-" belongs_to:"user"`
	UserID           uuid.UUID          `json:"-" db:"user_id"`
	CreatedAt        time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at" db:"updated_at"`
	Status           string             `json:"status" db:"status"`
	FriendlyName     string             `json:"friendly_name,omitempty" db:"friendly_name"`
	Secret           string             `json:"-" db:"secret"`
	FactorType       string             `json:"factor_type" db:"factor_type"`
	Challenge        []Challenge        `json:"-" has_many:"challenges"`
	Phone            storage.NullString `json:"phone" db:"phone"`
	LastChallengedAt *time.Time         `json:"last_challenged_at" db:"last_challenged_at"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, friendlyName string, factorType string, state FactorState) *Factor {
	id := uuid.Must(uuid.NewV4())

	factor := &Factor{
		ID:           id,
		UserID:       user.ID,
		Status:       state.String(),
		FriendlyName: friendlyName,
		FactorType:   factorType,
	}
	return factor
}

func NewTOTPFactor(user *User, friendlyName string) *Factor {
	return NewFactor(user, friendlyName, TOTP, FactorStateUnverified)
}

func NewPhoneFactor(user *User, phone, friendlyName string) *Factor {
	factor := NewFactor(user, friendlyName, Phone, FactorStateUnverified)
	factor.Phone = storage.NullString(phone)
	return factor
}

func (f *Factor) SetSecret(secret string, encrypt bool, encryptionKeyID, encryptionKey string) error {
	f.Secret = secret
	if encrypt {
		es, err := crypto.NewEncryptedString(f.ID.String(), []byte(secret), encryptionKeyID, encryptionKey)
		if err != nil {
			return err
		}

		f.Secret = es.String()
	}

	return nil
}

func (f *Factor) GetSecret(decryptionKeys map[string]string, encrypt bool, encryptionKeyID string) (string, bool, error) {
	if es := crypto.ParseEncryptedString(f.Secret); es != nil {
		bytes, err := es.Decrypt(f.ID.String(), decryptionKeys)
		if err != nil {
			return "", false, err
		}

		return string(bytes), encrypt && es.ShouldReEncrypt(encryptionKeyID), nil
	}

	return f.Secret, encrypt, nil
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

func DeleteUnverifiedFactors(tx *storage.Connection, user *User, factorType string) error {
	if err := tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Factor{}}).TableName()+" WHERE user_id = ? and status = ? and factor_type = ?", user.ID, FactorStateUnverified.String(), factorType).Exec(); err != nil {
		return err
	}

	return nil
}

func (f *Factor) CreateChallenge(ipAddress string) *Challenge {
	id := uuid.Must(uuid.NewV4())
	challenge := &Challenge{
		ID:        id,
		FactorID:  f.ID,
		IPAddress: ipAddress,
	}

	return challenge
}
func (f *Factor) WriteChallengeToDatabase(tx *storage.Connection, challenge *Challenge) error {
	if challenge.FactorID != f.ID {
		return errors.New("Can only write challenges that you own")
	}
	now := time.Now()
	f.LastChallengedAt = &now
	if terr := tx.Create(challenge); terr != nil {
		return terr
	}
	if err := tx.UpdateOnly(f, "last_challenged_at"); err != nil {
		return err
	}
	return nil
}

func (f *Factor) CreatePhoneChallenge(ipAddress string, otpCode string, encrypt bool, encryptionKeyID, encryptionKey string) (*Challenge, error) {
	phoneChallenge := f.CreateChallenge(ipAddress)
	if err := phoneChallenge.SetOtpCode(otpCode, encrypt, encryptionKeyID, encryptionKey); err != nil {
		return nil, err
	}
	return phoneChallenge, nil
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

func (f *Factor) IsUnverified() bool {
	return f.Status == FactorStateUnverified.String()
}

func (f *Factor) IsPhoneFactor() bool {
	return f.FactorType == Phone
}

func (f *Factor) FindChallengeByID(conn *storage.Connection, challengeID uuid.UUID) (*Challenge, error) {
	var challenge Challenge
	err := conn.Q().Where("id = ? and factor_id = ?", challengeID, f.ID).First(&challenge)
	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, ChallengeNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &challenge, nil
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

func (f *Factor) FindLatestUnexpiredChallenge(tx *storage.Connection, expiryDuration float64) (*Challenge, error) {
	now := time.Now()
	var challenge Challenge
	expirationTime := now.Add(time.Duration(expiryDuration) * time.Second)

	err := tx.Where("sent_at > ? and factor_id = ?", expirationTime, f.ID).
		Order("sent_at desc").
		First(&challenge)

	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, ChallengeNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &challenge, nil
}
