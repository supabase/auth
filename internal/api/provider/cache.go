package provider

import (
	"context"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultOIDCProviderCacheTTL is the default time-to-live for cached OIDC providers
	// 1 hour is a reasonable default as OIDC discovery documents rarely change
	DefaultOIDCProviderCacheTTL = 1 * time.Hour
)

// OIDCProviderCache provides thread-safe caching of OIDC provider instances
// to avoid redundant HTTP calls to OIDC discovery endpoints (.well-known/openid-configuration)
type OIDCProviderCache struct {
	mu      sync.RWMutex
	entries map[string]*oidcCacheEntry

	// Default TTL for cache entries
	defaultTTL time.Duration
}

type oidcCacheEntry struct {
	provider  *oidc.Provider
	createdAt time.Time
	expiresAt time.Time
}

// Global default OIDC provider cache instance
var defaultOIDCProviderCache = NewOIDCProviderCache(DefaultOIDCProviderCacheTTL)

// NewOIDCProviderCache creates a new OIDC provider cache instance with specified TTL
func NewOIDCProviderCache(ttl time.Duration) *OIDCProviderCache {
	if ttl <= 0 {
		ttl = DefaultOIDCProviderCacheTTL
	}
	return &OIDCProviderCache{
		entries:    make(map[string]*oidcCacheEntry),
		defaultTTL: ttl,
	}
}

// SetDefaultOIDCProviderCacheTTL updates the default OIDC provider cache TTL
// This should be called during application initialization with the configured value
func SetDefaultOIDCProviderCacheTTL(ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultOIDCProviderCacheTTL
	}
	defaultOIDCProviderCache.mu.Lock()
	defer defaultOIDCProviderCache.mu.Unlock()
	defaultOIDCProviderCache.defaultTTL = ttl
}

// Get returns a cached OIDC provider or creates a new one if not cached or expired.
// Uses the cache's default TTL (1 hour).
// This method is thread-safe and supports concurrent access.
//
// Parameters:
//   - ctx: Context for the OIDC provider creation (only used if cache miss)
//   - issuer: OIDC issuer URL (e.g., "https://accounts.google.com")
//
// Returns the cached or newly created provider instance
func (c *OIDCProviderCache) Get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	now := time.Now()

	// Fast path: check if cached and not expired (read lock only)
	c.mu.RLock()
	entry, exists := c.entries[issuer]
	c.mu.RUnlock()

	if exists && now.Before(entry.expiresAt) {
		logrus.WithFields(logrus.Fields{
			"issuer":     issuer,
			"created_at": entry.createdAt,
			"expires_at": entry.expiresAt,
		}).Debug("OIDC provider cache hit")
		return entry.provider, nil
	}

	// Slow path: need to create new provider (write lock required)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have created it)
	if entry, exists := c.entries[issuer]; exists && now.Before(entry.expiresAt) {
		logrus.WithField("issuer", issuer).Debug("OIDC provider cache hit after lock acquisition")
		return entry.provider, nil
	}

	// Create provider with background context to ensure it's not tied to request lifecycle
	// Use a background context with a deadline if the original context has one
	bgCtx := context.Background()
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		bgCtx, cancel = context.WithDeadline(bgCtx, deadline)
		defer cancel()
	}

	provider, err := oidc.NewProvider(bgCtx, issuer)
	if err != nil {
		logrus.WithError(err).WithField("issuer", issuer).Error("Failed to create OIDC provider")
		return nil, err
	}

	expiresAt := now.Add(c.defaultTTL)
	c.entries[issuer] = &oidcCacheEntry{
		provider:  provider,
		createdAt: now,
		expiresAt: expiresAt,
	}

	return provider, nil
}

// Invalidate removes a specific OIDC provider from the cache
// Useful for manual cache invalidation or testing
func (c *OIDCProviderCache) Invalidate(issuer string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[issuer]; exists {
		delete(c.entries, issuer)
	}
}

// Clear removes all entries from the cache
// Primarily used for testing
func (c *OIDCProviderCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*oidcCacheEntry)
}

// Size returns the current number of cached OIDC providers
func (c *OIDCProviderCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GetDefaultOIDCProviderCache returns the global default OIDC provider cache instance
func GetDefaultOIDCProviderCache() *OIDCProviderCache {
	return defaultOIDCProviderCache
}
