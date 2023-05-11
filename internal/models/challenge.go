package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
	"time"
)

type Challenge struct {
	ID         uuid.UUID  `json:"challenge_id" db:"id"`
	FactorID   uuid.UUID  `json:"factor_id" db:"factor_id"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	IPAddress  string     `json:"ip_address" db:"ip_address"`
	Factor     *Factor    `json:"factor,omitempty" belongs_to:"factor"`
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
	return tableName
}

func NewChallenge(factor *Factor, ipAddress string) (*Challenge, error) {
	id := uuid.Must(uuid.NewV4())

	challenge := &Challenge{
		ID:        id,
		FactorID:  factor.ID,
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
