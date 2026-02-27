package provider

import (
	"context"
	"testing"
	"time"
)

func TestNewOIDCProviderCache(t *testing.T) {
	t.Run("creates cache with valid TTL", func(t *testing.T) {
		cache := NewOIDCProviderCache(30 * time.Minute)
		if cache == nil {
			t.Fatal("expected cache to be created")
		}
		if cache.defaultTTL != 30*time.Minute {
			t.Errorf("expected TTL to be 30m, got %v", cache.defaultTTL)
		}
	})

	t.Run("falls back to default TTL when invalid", func(t *testing.T) {
		cache := NewOIDCProviderCache(0)
		if cache.defaultTTL != DefaultOIDCProviderCacheTTL {
			t.Errorf("expected TTL to be %v, got %v", DefaultOIDCProviderCacheTTL, cache.defaultTTL)
		}

		cache = NewOIDCProviderCache(-1 * time.Hour)
		if cache.defaultTTL != DefaultOIDCProviderCacheTTL {
			t.Errorf("expected TTL to be %v, got %v", DefaultOIDCProviderCacheTTL, cache.defaultTTL)
		}
	})
}

func TestSetDefaultOIDCProviderCacheTTL(t *testing.T) {
	// Save original state
	originalCache := defaultOIDCProviderCache
	defer func() {
		defaultOIDCProviderCache = originalCache
	}()

	// Create test cache
	defaultOIDCProviderCache = NewOIDCProviderCache(DefaultOIDCProviderCacheTTL)

	t.Run("updates default cache TTL", func(t *testing.T) {
		newTTL := 45 * time.Minute
		SetDefaultOIDCProviderCacheTTL(newTTL)
		if defaultOIDCProviderCache.defaultTTL != newTTL {
			t.Errorf("expected TTL to be %v, got %v", newTTL, defaultOIDCProviderCache.defaultTTL)
		}
	})

	t.Run("falls back to default when invalid", func(t *testing.T) {
		SetDefaultOIDCProviderCacheTTL(0)
		if defaultOIDCProviderCache.defaultTTL != DefaultOIDCProviderCacheTTL {
			t.Errorf("expected TTL to be %v, got %v", DefaultOIDCProviderCacheTTL, defaultOIDCProviderCache.defaultTTL)
		}

		SetDefaultOIDCProviderCacheTTL(-1 * time.Hour)
		if defaultOIDCProviderCache.defaultTTL != DefaultOIDCProviderCacheTTL {
			t.Errorf("expected TTL to be %v, got %v", DefaultOIDCProviderCacheTTL, defaultOIDCProviderCache.defaultTTL)
		}
	})
}

func TestOIDCProviderCacheInvalidate(t *testing.T) {
	cache := NewOIDCProviderCache(1 * time.Hour)

	// Manually add a mock entry
	cache.entries["test-issuer"] = &oidcCacheEntry{
		provider:  nil,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	t.Run("invalidates existing entry", func(t *testing.T) {
		if cache.Size() != 1 {
			t.Errorf("expected cache size to be 1, got %d", cache.Size())
		}

		cache.Invalidate("test-issuer")

		if cache.Size() != 0 {
			t.Errorf("expected cache size to be 0 after invalidation, got %d", cache.Size())
		}
	})

	t.Run("invalidating non-existent entry is no-op", func(t *testing.T) {
		// Should not panic or error
		cache.Invalidate("non-existent")
		if cache.Size() != 0 {
			t.Errorf("expected cache size to remain 0, got %d", cache.Size())
		}
	})
}

func TestOIDCProviderCacheClear(t *testing.T) {
	cache := NewOIDCProviderCache(1 * time.Hour)

	// Add multiple mock entries
	cache.entries["issuer-1"] = &oidcCacheEntry{
		provider:  nil,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	cache.entries["issuer-2"] = &oidcCacheEntry{
		provider:  nil,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	if cache.Size() != 2 {
		t.Fatalf("expected cache size to be 2, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("expected cache size to be 0 after clear, got %d", cache.Size())
	}
}

func TestOIDCProviderCacheSize(t *testing.T) {
	cache := NewOIDCProviderCache(1 * time.Hour)

	if cache.Size() != 0 {
		t.Errorf("expected initial cache size to be 0, got %d", cache.Size())
	}

	// Add entries
	for i := 0; i < 5; i++ {
		cache.entries[string(rune(i))] = &oidcCacheEntry{
			provider:  nil,
			createdAt: time.Now(),
			expiresAt: time.Now().Add(1 * time.Hour),
		}
	}

	if cache.Size() != 5 {
		t.Errorf("expected cache size to be 5, got %d", cache.Size())
	}
}

func TestGetDefaultOIDCProviderCache(t *testing.T) {
	cache := GetDefaultOIDCProviderCache()
	if cache == nil {
		t.Fatal("expected GetDefaultOIDCProviderCache to return non-nil cache")
	}

	// Should return the same instance
	cache2 := GetDefaultOIDCProviderCache()
	if cache != cache2 {
		t.Error("expected GetDefaultOIDCProviderCache to return same instance")
	}
}

func TestOIDCProviderCacheExpiration(t *testing.T) {
	cache := NewOIDCProviderCache(100 * time.Millisecond)

	// Add an entry that will expire soon
	cache.entries["test-issuer"] = &oidcCacheEntry{
		provider:  nil,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(50 * time.Millisecond),
	}

	if cache.Size() != 1 {
		t.Fatalf("expected cache size to be 1, got %d", cache.Size())
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Expired entry should still be in map (not automatically removed)
	if cache.Size() != 1 {
		t.Errorf("expected cache size to still be 1 (expired entries not auto-removed), got %d", cache.Size())
	}

	// But Get should not return it (it checks expiration)
	ctx := context.Background()
	// This will attempt to create a real OIDC provider which will fail,
	// but that's expected - we're testing that expired entries trigger recreation
	_, err := cache.Get(ctx, "test-issuer")
	// We expect an error since we're using an invalid issuer
	if err == nil {
		t.Error("expected error when trying to create provider with invalid issuer")
	}
}

func TestOIDCProviderCacheConcurrency(t *testing.T) {
	cache := NewOIDCProviderCache(1 * time.Hour)

	// Add initial entry using proper locking
	cache.mu.Lock()
	cache.entries["concurrent-test"] = &oidcCacheEntry{
		provider:  nil,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	cache.mu.Unlock()

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cache.Size()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Test concurrent writes using public API (which has proper locking)
	for i := 0; i < 10; i++ {
		go func(id int) {
			// Use Invalidate which has proper locking
			cache.Invalidate("concurrent-test")
			// Clear also has proper locking
			cache.Clear()
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic or race
	_ = cache.Size()
}
