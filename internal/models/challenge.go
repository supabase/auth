package models

import (
	"database/sql"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	"time"
)

type Challenge struct {
	ID         uuid.UUID  `json:"challenge_id" db:"id"`
	FactorID   uuid.UUID  `json:"factor_id" db:"factor_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	IPAddress  string     `json:"ip_address" db:"ip_address"`
	Factor     *Factor    `json:"factor,omitempty" belongs_to:"factor"`
	OtpCode    string     `json:"otp_code,omitempty" db:"otp_code"`
	SentAt     *time.Time `json:"sent_at,omitempty" db:"sent_at"`
	WebauthnChallenge *string    `json:"webauthn_challenge,omitempty" db:"webauthn_challenge"`
	UserVerification  *string    `json:"user_verification,omitempty" db:"user_verification"`
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
}


func FindChallengeByID(conn *storage.Connection, challengeID uuid.UUID) (*Challenge, error) {
	var challenge Challenge
	err := conn.Find(&challenge, challengeID)
	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, ChallengeNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &challenge, nil
}


func NewWebauthnChallenge(factor *Factor, ipAddress string, webauthnChallenge string) *Challenge {
	id := uuid.Must(uuid.NewV4())
	defaultVerification := "prefeerred"

	challenge := &Challenge{
		ID:                id,
		FactorID:          factor.ID,
		IPAddress:         ipAddress,
		WebauthnChallenge: &webauthnChallenge,
		//TODO: Have a more sane default
		UserVerification: &defaultVerification,
	}
	return challenge
}

func FindChallengeByID(conn *storage.Connection, challengeID uuid.UUID) (*Challenge, error) {
	var challenge Challenge
	err := conn.Find(&challenge, challengeID)
	if err != nil && errors.Cause(err) == sql.ErrNoRows {
		return nil, ChallengeNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	return &challenge, nil
}

// Update the verification timestamp
func (c *Challenge) Verify(tx *storage.Connection) error {
	now := time.Now()
	c.VerifiedAt = &now
	return tx.UpdateOnly(c, "verified_at")
}

func (c *Challenge) HasExpired(expiryDuration float64) bool {
	return time.Now().After(c.GetExpiryTime(expiryDuration))
}

func (c *Challenge) GetExpiryTime(expiryDuration float64) time.Time {
	return c.CreatedAt.Add(time.Second * time.Duration(expiryDuration))
}

func (c *Challenge) SetOtpCode(otpCode string, encrypt bool, encryptionKeyID, encryptionKey string) error {
	c.OtpCode = otpCode
	if encrypt {
		es, err := crypto.NewEncryptedString(c.ID.String(), []byte(otpCode), encryptionKeyID, encryptionKey)
		if err != nil {
			return err
		}

		c.OtpCode = es.String()
	}
	return nil

}

func (c *Challenge) GetOtpCode(decryptionKeys map[string]string, encrypt bool, encryptionKeyID string) (string, bool, error) {
	if es := crypto.ParseEncryptedString(c.OtpCode); es != nil {
		bytes, err := es.Decrypt(c.ID.String(), decryptionKeys)
		if err != nil {
			return "", false, err
		}

		return string(bytes), encrypt && es.ShouldReEncrypt(encryptionKeyID), nil
	}

	return c.OtpCode, encrypt, nil
}

func (c *Challenge) ToSession(userID uuid.UUID, challengeExpiryDuration float64) webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:        *c.WebauthnChallenge,
		UserID:           []byte(userID.String()),
		Expires:          c.GetExpiryTime(challengeExpiryDuration),
		UserVerification: protocol.UserVerificationRequirement(*c.UserVerification),
	}
}

type WebauthnSession struct {
	*webauthn.SessionData
}

func (ws *WebauthnSession) ToChallenge(factorID uuid.UUID, ipAddress string) *Challenge {
	id := uuid.Must(uuid.NewV4())
	defaultVerification := "preferred"
	return &Challenge{
		ID:                id,
		FactorID:          factorID,
		IPAddress:         ipAddress,
		UserVerification:  &defaultVerification,
		WebauthnChallenge: &ws.Challenge,
	}

}
