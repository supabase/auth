package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type Challenge struct {
	ID         uuid.UUID  `json:"challenge_id" db:"id"`
	FactorID   uuid.UUID  `json:"factor_id" db:"factor_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time `json:"verified_at" db:"verified_at"`
	IPAddress  string     `json:"ip_address" db:"ip_address"`
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
}

const ChallengePrefix = "challenge"

func NewChallenge(factor *Factor, ipAddress string) (*Challenge, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	challenge := &Challenge{
		ID:       id,
		FactorID: factor.ID,
		// TODO(Joel): Modify to pass in IP address)
		IPAddress: ipAddress,
	}
	return challenge, nil
}

func FindChallengeByChallengeID(tx *storage.Connection, challengeID uuid.UUID) (*Challenge, error) {
	challenge, err := findChallenge(tx, "id = ?", challengeID)
	if err != nil {
		return nil, ChallengeNotFoundError{}
	}
	return challenge, nil
}

// Update the verification timestamp
func (f *Challenge) Verify(tx *storage.Connection) error {
	now := time.Now()
	f.VerifiedAt = &now
	return tx.UpdateOnly(f, "verified_at")
}

func findChallenge(tx *storage.Connection, query string, args ...interface{}) (*Challenge, error) {
	obj := &Challenge{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, ChallengeNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding challenge")
	}
	return obj, nil
}
