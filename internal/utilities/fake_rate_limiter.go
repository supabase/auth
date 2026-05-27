package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/supabase/auth/internal/storage"
)

type FakeRateLimit struct {
	EmailHash     string    `db:"email_hash"`
	LastRequestAt time.Time `db:"last_request_at"`
}

// TableName returns the table name
func (FakeRateLimit) TableName() string {
	return "fake_rate_limits"
}

// CheckFakeRateLimit simulates a rate limit check for a non-existent email.
// It returns the timestamp of the last request if it was rate limited, or nil if not.
func CheckFakeRateLimit(db *storage.Connection, email string, frequency time.Duration) *time.Time {
	hash := sha256.Sum256([]byte(email))
	hashStr := hex.EncodeToString(hash[:])

	var lastReq *time.Time
	_ = db.Transaction(func(tx *storage.Connection) error {
		// Lock the row
		existing := &FakeRateLimit{}
		err := tx.RawQuery(`SELECT last_request_at FROM fake_rate_limits WHERE email_hash = ? FOR UPDATE`, hashStr).First(existing)
		
		now := time.Now()
		if err == nil { // Row exists
			if now.Sub(existing.LastRequestAt) < frequency {
				// Rate limited!
				last := existing.LastRequestAt
				lastReq = &last
				return nil
			}
			// Not rate limited, update it
			_ = tx.RawQuery(`UPDATE fake_rate_limits SET last_request_at = ? WHERE email_hash = ?`, now, hashStr).Exec()
		} else { // Row doesn't exist or error
			// Insert it
			_ = tx.RawQuery(`INSERT INTO fake_rate_limits (email_hash, last_request_at) VALUES (?, ?) ON CONFLICT DO NOTHING`, hashStr, now).Exec()
		}
		return nil
	})

	return lastReq
}

// CleanupFakeRateLimitCache removes expired entries from the cache.
// Call this periodically or when necessary to prevent unbounded memory growth.
func CleanupFakeRateLimitCache(db *storage.Connection, frequency time.Duration) {
	_ = db.RawQuery(
		`DELETE FROM fake_rate_limits WHERE EXTRACT(EPOCH FROM (NOW() - last_request_at)) > ?`,
		frequency.Seconds(),
	).Exec()
}
