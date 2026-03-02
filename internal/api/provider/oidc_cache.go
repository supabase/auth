package provider

import (
	"context"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/sync/singleflight"
)

type oidcCacheEntry struct {
	provider  *oidc.Provider
	fetchedAt time.Time
}

// OIDCProviderCache caches *oidc.Provider objects keyed by issuer URL.
// This avoids re-fetching the OIDC discovery document on every request.
// JWKS fetching/caching is handled separately by the oidc library itself,
// it lazy-loads the key set on the first call to Verify and manages its own cache.
// It uses singleflight to deduplicate concurrent fetches for the same issuer.
type OIDCProviderCache struct {
	mu    sync.RWMutex
	cache map[string]*oidcCacheEntry
	sf    singleflight.Group
	ttl   time.Duration
	now   func() time.Time // injectable for tests
}

// NewOIDCProviderCache creates a new cache with the given TTL.
func NewOIDCProviderCache(ttl time.Duration) *OIDCProviderCache {
	return &OIDCProviderCache{
		cache: make(map[string]*oidcCacheEntry),
		ttl:   ttl,
		now:   time.Now,
	}
}

// GetProvider returns a cached *oidc.Provider for the given issuer, fetching
// it via oidc.NewProvider if not cached or expired. Concurrent requests for
// the same issuer are deduplicated via singleflight.
func (c *OIDCProviderCache) GetProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	now := c.now()

	// Fast path: read-lock check
	c.mu.RLock()
	if entry, ok := c.cache[issuer]; ok && now.Sub(entry.fetchedAt) < c.ttl {
		c.mu.RUnlock()
		return entry.provider, nil
	}
	c.mu.RUnlock()

	// Slow path: singleflight fetch
	val, err, _ := c.sf.Do(issuer, func() (interface{}, error) {
		p, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.cache[issuer] = &oidcCacheEntry{
			provider:  p,
			fetchedAt: c.now(),
		}
		c.mu.Unlock()

		return p, nil
	})
	if err != nil {
		// Serve stale entry if available — keeps auth working during
		// transient network failures or issuer outages.
		c.mu.RLock()
		if entry, ok := c.cache[issuer]; ok {
			c.mu.RUnlock()
			return entry.provider, nil
		}
		c.mu.RUnlock()
		return nil, err
	}

	return val.(*oidc.Provider), nil
}

// Invalidate removes a cached provider for the given issuer.
func (c *OIDCProviderCache) Invalidate(issuer string) {
	c.mu.Lock()
	delete(c.cache, issuer)
	c.mu.Unlock()
}

// Clear removes all cached providers.
func (c *OIDCProviderCache) Clear() {
	c.mu.Lock()
	c.cache = make(map[string]*oidcCacheEntry)
	c.mu.Unlock()
}
