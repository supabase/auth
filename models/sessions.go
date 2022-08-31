package models

import (
	"database/sql"
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

type Session struct {
	ID        uuid.UUID `json:"-" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

func (Session) TableName() string {
	tableName := "sessions"
	return tableName
}

func NewSession(user *User, factorID string) (*Session, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique session id")
	}

	session := &Session{
		ID:     id,
		UserID: user.ID,
		FactorID: factorID,
	}
	return session, nil
}

func CreateSession(tx *storage.Connection, user *User) (*Session, error) {
	session, err := NewSession(user)
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


// Logout deletes all sessions for a user.
func Logout(tx *storage.Connection, userId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ?", userId).Exec()
}

func LogoutSession(tx *storage.Connection, sessionId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE id = ?", sessionId).Exec()
}
