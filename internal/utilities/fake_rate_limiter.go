package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

var (
	// fakeRateLimitCache stores hashes of non-existent emails and their last request timestamp.
	fakeRateLimitCache sync.Map
)

// CheckFakeRateLimit simulates a rate limit check for a non-existent email.
// It returns the timestamp of the last request if it was rate limited, or nil if not.
func CheckFakeRateLimit(email string, frequency time.Duration) *time.Time {
	hash := sha256.Sum256([]byte(email))
	hashStr := hex.EncodeToString(hash[:])

	now := time.Now()
	if val, ok := fakeRateLimitCache.Load(hashStr); ok {
		lastReq := val.(time.Time)
		if now.Sub(lastReq) < frequency {
			return &lastReq // Rate limited
		}
	}

	fakeRateLimitCache.Store(hashStr, now)
	return nil // Not rate limited
}

// CleanupFakeRateLimitCache removes expired entries from the cache.
// Call this periodically or when necessary to prevent unbounded memory growth.
func CleanupFakeRateLimitCache(frequency time.Duration) {
	now := time.Now()
	fakeRateLimitCache.Range(func(key, value interface{}) bool {
		lastReq := value.(time.Time)
		if now.Sub(lastReq) > frequency {
			fakeRateLimitCache.Delete(key)
		}
		return true
	})
}
