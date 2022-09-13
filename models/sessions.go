package models

import (
	"database/sql"
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

const AAL1 = "aal1"
const AAL2 = "aal2"
const AAL3 = "aal3"

type Session struct {
	ID        uuid.UUID  `json:"-" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	FactorID  uuid.UUID  `json:"factor_id" db:"factor_id"`
	AMRClaims []AMRClaim `json:"amr_claims" has_many:"amr_claims"`
	AAL       string     `json:"aal" db:"aal"`
}

func (Session) TableName() string {
	tableName := "sessions"
	return tableName
}

func NewSession(user *User, factorID uuid.UUID) (*Session, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique session id")
	}

	session := &Session{
		ID:       id,
		UserID:   user.ID,
		FactorID: factorID,
		AAL:      AAL1,
	}
	return session, nil
}

func CreateSession(tx *storage.Connection, user *User, factorID uuid.UUID) (*Session, error) {
	session, err := NewSession(user, factorID)
	if err != nil {
		return nil, err
	}
	if err := tx.Create(session); err != nil {
		return nil, errors.Wrap(err, "error creating session")
	}
	return session, nil
}

func FindSessionById(tx *storage.Connection, id uuid.UUID) (*Session, error) {
	session := &Session{}
	if err := tx.Eager().Q().Where("id = ?", id).First(session); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SessionNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}
	return session, nil
}

func FindSessionByUserID(tx *storage.Connection, userId uuid.UUID) (*Session, error) {
	session := &Session{}
	if err := tx.Eager().Q().Where("user_id = ?", userId).First(session); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SessionNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}
	return session, nil
}

func InvalidateOtherFactorAssociatedSessions(tx *storage.Connection, currentSessionID, userID, factorID uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ? AND factor_id = ? AND id != ?", userID, factorID, currentSessionID).Exec()
}

func InvalidateSessionsWithAALLessThan(tx *storage.Connection, userID uuid.UUID, level string) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ? AND aal < ?", userID, level).Exec()
}

// Logout deletes all sessions for a user.
func Logout(tx *storage.Connection, userId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ?", userId).Exec()
}

func LogoutSession(tx *storage.Connection, sessionId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE id = ?", sessionId).Exec()
}

func (s *Session) UpdateAssociatedFactor(tx *storage.Connection, factorID uuid.UUID) error {
	s.FactorID = factorID
	return tx.Update(s)

}

func (s *Session) UpdateAAL(tx *storage.Connection, aal string) error {
	s.AAL = aal
	return tx.Update(s)
}
