package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/sync/singleflight"
)

// oidcDiscoveryHTTPClient bounds the discovery fetch so a slow or hung
// upstream cannot wedge an auth request indefinitely. JWKS fetches use
// go-oidc's own client and are unaffected.
var oidcDiscoveryHTTPClient = &http.Client{Timeout: 10 * time.Second}

// oidcSupportedAlgorithms mirrors the set that go-oidc's discovery path filters
// against internally. We duplicate it here because the manual ProviderConfig
// path doesn't go through that filter — without it, a misconfigured upstream
// could push a verifier into accepting algorithms go-oidc doesn't actually
// support. Keep in sync with go-oidc's supportedAlgorithms.
var oidcSupportedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"EdDSA": true,
}

type oidcDiscoveryDoc struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

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

// GetProviderFromURL returns an *oidc.Provider built from an explicit discovery URL,
// rather than the standard {issuer}/.well-known/openid-configuration path.
// The result is cached and deduplicated (singleflight) under the issuer key,
// so Invalidate(issuer) continues to work unchanged.
func (c *OIDCProviderCache) GetProviderFromURL(ctx context.Context, issuer, discoveryURL string) (*oidc.Provider, error) {
	now := c.now()

	c.mu.RLock()
	if entry, ok := c.cache[issuer]; ok && now.Sub(entry.fetchedAt) < c.ttl {
		c.mu.RUnlock()
		return entry.provider, nil
	}
	c.mu.RUnlock()

	val, err, _ := c.sf.Do(issuer, func() (interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, fmt.Errorf("oidc: failed to build discovery request: %w", err)
		}
		resp, err := oidcDiscoveryHTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("oidc: discovery request to %s failed: %w", discoveryURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("oidc: discovery request to %s returned %s", discoveryURL, resp.Status)
		}

		var doc oidcDiscoveryDoc
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return nil, fmt.Errorf("oidc: failed to decode discovery document from %s: %w", discoveryURL, err)
		}

		if doc.Issuer != issuer {
			return nil, fmt.Errorf("oidc: issuer mismatch, expected %q got %q", issuer, doc.Issuer)
		}

		var algs []string
		for _, a := range doc.Algorithms {
			if oidcSupportedAlgorithms[a] {
				algs = append(algs, a)
			}
		}

		p := (&oidc.ProviderConfig{
			IssuerURL:   doc.Issuer,
			AuthURL:     doc.AuthURL,
			TokenURL:    doc.TokenURL,
			UserInfoURL: doc.UserInfoURL,
			JWKSURL:     doc.JWKSURL,
			Algorithms:  algs,
		}).NewProvider(ctx)

		c.mu.Lock()
		c.cache[issuer] = &oidcCacheEntry{
			provider:  p,
			fetchedAt: c.now(),
		}
		c.mu.Unlock()

		return p, nil
	})
	if err != nil {
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
