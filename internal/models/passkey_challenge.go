package models

import (
	"database/sql"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type PasskeyChallenge struct {
	ID                  uuid.UUID            `json:"id" db:"id"`
	UserID              *uuid.UUID           `json:"user_id" db:"user_id"`
	WebAuthnSessionData *WebAuthnSessionData `json:"web_authn_session_data,omitempty" db:"web_authn_session_data"`
	IPAddress           string               `json:"ip_address" db:"ip_address"`
	CreatedAt           time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at" db:"updated_at"`
}

func (PasskeyChallenge) TableName() string {
	return "passkey_challenges"
}

func NewPasskeyChallenge(sessionData *webauthn.SessionData, userID *uuid.UUID, ipAddress string) *PasskeyChallenge {
	id := uuid.Must(uuid.NewV4())
	var ws *WebAuthnSessionData
	if sessionData != nil {
		ws = &WebAuthnSessionData{SessionData: sessionData}
	}
	return &PasskeyChallenge{
		ID:                  id,
		UserID:              userID,
		WebAuthnSessionData: ws,
		IPAddress:           ipAddress,
	}
}

func FindPasskeyChallengeByID(tx *storage.Connection, id uuid.UUID) (*PasskeyChallenge, error) {
	challenge := &PasskeyChallenge{}
	if err := tx.Find(challenge, id); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, &PasskeyChallengeNotFoundError{}
		}
		return nil, err
	}
	return challenge, nil
}

func (c *PasskeyChallenge) HasExpired(expiryDuration time.Duration) bool {
	return time.Now().After(c.CreatedAt.Add(expiryDuration))
}

func (c *PasskeyChallenge) UpdateUserID(tx *storage.Connection, userID uuid.UUID) error {
	c.UserID = &userID
	return tx.UpdateOnly(c, "user_id", "updated_at")
}

func (c *PasskeyChallenge) UpdateSession(tx *storage.Connection, sessionData *webauthn.SessionData) error {
	if sessionData == nil {
		c.WebAuthnSessionData = nil
	} else {
		c.WebAuthnSessionData = &WebAuthnSessionData{SessionData: sessionData}
	}
	return tx.UpdateOnly(c, "web_authn_session_data", "updated_at")
}
