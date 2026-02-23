package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestOIDCServer creates a test OIDC discovery server that counts fetches.
func newTestOIDCServer(fetchCount *atomic.Int64) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if fetchCount != nil {
				fetchCount.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"userinfo_endpoint":      server.URL + "/userinfo",
				"jwks_uri":               server.URL + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []interface{}{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func TestOIDCProviderCache_CacheHitAndMiss(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	cache := NewOIDCProviderCache(time.Hour)

	// First call: cache miss
	p1, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	require.NotNil(t, p1)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Second call: cache hit
	p2, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	require.NotNil(t, p2)
	assert.Equal(t, int64(1), fetchCount.Load()) // no additional fetch

	// Same provider returned
	assert.Equal(t, p1, p2)
}

func TestOIDCProviderCache_TTLExpiration(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	now := time.Now()
	cache := NewOIDCProviderCache(time.Hour)
	cache.now = func() time.Time { return now }

	// First fetch
	_, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Advance time past TTL
	now = now.Add(2 * time.Hour)

	// Should re-fetch
	_, err = cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(2), fetchCount.Load())
}

func TestOIDCProviderCache_Singleflight(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	cache := NewOIDCProviderCache(time.Hour)

	// Launch multiple concurrent fetches for the same issuer
	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = cache.GetProvider(context.Background(), server.URL)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err)
	}

	// Singleflight should have deduplicated to 1 fetch
	assert.Equal(t, int64(1), fetchCount.Load())
}

func TestOIDCProviderCache_Invalidate(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	cache := NewOIDCProviderCache(time.Hour)

	// Prime the cache
	_, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Invalidate
	cache.Invalidate(server.URL)

	// Should re-fetch
	_, err = cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(2), fetchCount.Load())
}

func TestOIDCProviderCache_Clear(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	cache := NewOIDCProviderCache(time.Hour)

	// Prime the cache
	_, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Clear all
	cache.Clear()

	// Should re-fetch
	_, err = cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(2), fetchCount.Load())
}

func TestOIDCProviderCache_MultipleIssuers(t *testing.T) {
	var fetchCount1 atomic.Int64
	server1 := newTestOIDCServer(&fetchCount1)
	defer server1.Close()

	var fetchCount2 atomic.Int64
	server2 := newTestOIDCServer(&fetchCount2)
	defer server2.Close()

	cache := NewOIDCProviderCache(time.Hour)

	// Fetch from two different issuers
	p1, err := cache.GetProvider(context.Background(), server1.URL)
	require.NoError(t, err)
	require.NotNil(t, p1)

	p2, err := cache.GetProvider(context.Background(), server2.URL)
	require.NoError(t, err)
	require.NotNil(t, p2)

	assert.Equal(t, int64(1), fetchCount1.Load())
	assert.Equal(t, int64(1), fetchCount2.Load())

	// Invalidate only one
	cache.Invalidate(server1.URL)

	_, err = cache.GetProvider(context.Background(), server1.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(2), fetchCount1.Load())

	// Second issuer still cached
	_, err = cache.GetProvider(context.Background(), server2.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount2.Load())
}

func TestOIDCProviderCache_ErrorNotCached(t *testing.T) {
	cache := NewOIDCProviderCache(time.Hour)

	// Non-existent issuer should return error
	_, err := cache.GetProvider(context.Background(), "http://127.0.0.1:1/nonexistent")
	require.Error(t, err)

	// Cache should still be empty
	cache.mu.RLock()
	assert.Empty(t, cache.cache)
	cache.mu.RUnlock()
}

func TestOIDCProviderCache_StaleOnError(t *testing.T) {
	var fetchCount atomic.Int64
	server := newTestOIDCServer(&fetchCount)
	defer server.Close()

	now := time.Now()
	cache := NewOIDCProviderCache(time.Hour)
	cache.now = func() time.Time { return now }

	// Prime the cache
	p1, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	require.NotNil(t, p1)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Advance time past TTL so the entry is stale
	now = now.Add(2 * time.Hour)

	// Shut down the server to simulate a network failure
	server.Close()

	// Should return the stale cached entry instead of an error
	p2, err := cache.GetProvider(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, p1, p2)
}

func TestOIDCProviderCache_TTLPassedThrough(t *testing.T) {
	cache := NewOIDCProviderCache(30 * time.Minute)
	assert.Equal(t, 30*time.Minute, cache.ttl)
}
