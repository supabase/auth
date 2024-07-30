package models

import (
	"database/sql/driver"
	"fmt"

	"encoding/json"
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
	// TODO: prepend webauthn_ to this and also credential on factor
	SessionData *SessionData `json:"session_data,omitempty" db:"session_data"`
}

type SessionData struct {
	webauthn.SessionData
}

func (s *SessionData) Value() (driver.Value, error) {
	return json.Marshal(s)
}

func (s *SessionData) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected byte array but got %T", value)
	}

	return json.Unmarshal(bytes, s)
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
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

type WebAuthnSession struct {
	*webauthn.SessionData
}

func (ws *WebAuthnSession) ToChallenge(factorID uuid.UUID, ipAddress string) *Challenge {
	id := uuid.Must(uuid.NewV4())
	return &Challenge{
		ID:        id,
		FactorID:  factorID,
		IPAddress: ipAddress,
		SessionData: &SessionData{
			*ws.SessionData,
		},
	}

}
