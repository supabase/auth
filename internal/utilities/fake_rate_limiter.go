package utilities

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
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
func CheckFakeRateLimit(db *storage.Connection, email string, frequency time.Duration, secret []byte) *time.Time {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(email))
	hashStr := hex.EncodeToString(h.Sum(nil))

	var lastReq *time.Time
	_ = db.Transaction(func(tx *storage.Connection) error {
		// Pre-insert a sentinel row so the row always exists before we lock it.
		// This prevents two concurrent first-requests from both racing past FOR UPDATE.
		epoch := time.Unix(0, 0).UTC()
		_ = tx.RawQuery(`INSERT INTO fake_rate_limits (email_hash, last_request_at) VALUES (?, ?) ON CONFLICT DO NOTHING`, hashStr, epoch).Exec()

		// Lock the now-guaranteed-existing row
		existing := &FakeRateLimit{}
		if err := tx.RawQuery(`SELECT last_request_at FROM fake_rate_limits WHERE email_hash = ? FOR UPDATE`, hashStr).First(existing); err != nil {
			return err
		}

		now := time.Now()
		if now.Sub(existing.LastRequestAt) < frequency {
			// Rate limited!
			last := existing.LastRequestAt
			lastReq = &last
			return nil
		}
		// Not rate limited, update the timestamp
		_ = tx.RawQuery(`UPDATE fake_rate_limits SET last_request_at = ? WHERE email_hash = ?`, now, hashStr).Exec()
		return nil
	})

	// Probabilistic cleanup (10% chance) to prevent table unbounded growth
	if rand.Intn(10) == 0 {
		go CleanupFakeRateLimitCache(db, frequency)
	}

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
