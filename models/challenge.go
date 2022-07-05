package models

import (
	"database/sql"
	"fmt"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type Challenge struct {
	ID         string     `json:"challenge_id" db:"id"`
	FactorID   string     `json:"factor_id" db:"factor_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time `json:"verified_at" db:"verified_at"`
}

const CHALLENGE_PREFIX = "challenge"

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
}

func NewChallenge(factorID string) (*Challenge, error) {
	challenge := &Challenge{
		ID:       fmt.Sprintf("%s_%s", CHALLENGE_PREFIX, crypto.SecureToken()),
		FactorID: factorID,
	}
	return challenge, nil
}

func FindChallengeByChallengeID(tx *storage.Connection, challengeID string) (*Challenge, error) {
	challenge, err := findChallenge(tx, "id = ?", challengeID)
	if err != nil {
		return nil, ChallengeNotFoundError{}
	}
	return challenge, nil
}

func FindChallengesByFactorID(tx *storage.Connection, factorID string) ([]*Challenge, error) {
	challenges := []*Challenge{}
	if err := tx.Q().Where("factor_id = ?", factorID, true).All(&challenges); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return challenges, nil
		}
		return nil, errors.Wrap(err, "Error finding MFA Challenges for factor")
	}
	return challenges, nil
}

// Update the verification timestamp
func (f *Challenge) Verify(tx *storage.Connection) error {
	now := time.Now()
	f.VerifiedAt = &now
	return tx.UpdateOnly(f, "verifiedAt")
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
