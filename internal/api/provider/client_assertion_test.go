package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/conf/awskmsjwk"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestClock() *testClock               { return &testClock{t: time.Unix(1_800_000_000, 0)} }
func newTestCache(clock *testClock) *ClientAssertionCache {
	c := NewClientAssertionCache()
	c.now = clock.now
	return c
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func newTestSigningJwk(t *testing.T, raw any, kid string) jwk.Key {
	t.Helper()
	k, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, kid))
	require.NoError(t, k.Set(jwk.AlgorithmKey, "RS256"))
	require.NoError(t, k.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign}))
	return k
}

// newTestAssertionConfig returns a plain-key config and a counter of how many
// times the signing key was requested (once per signed assertion).
func newTestAssertionConfig(t *testing.T, key *rsa.PrivateKey, kid string) (*conf.ClientAssertionConfiguration, *atomic.Int32) {
	t.Helper()
	var signs atomic.Int32
	return &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: newTestSigningJwk(t, key, kid),
		SigningKey: func(context.Context) (any, error) {
			signs.Add(1)
			return key, nil
		},
	}, &signs
}

var testAssertionRequest = ClientAssertionRequest{
	ProviderID: "7f0c6a1e-1111-4222-8333-944445555666",
	ClientID:   "test-client-id",
	Audience:   "https://issuer.example.com",
}

func parseTestAssertion(t *testing.T, assertion string, pub *rsa.PublicKey) *jwt.Token {
	t.Helper()
	token, err := jwt.Parse(assertion, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(func() time.Time { return time.Unix(1_800_000_000, 0) }),
	)
	require.NoError(t, err)
	return token
}

func TestClientAssertionHeaderAndClaims(t *testing.T) {
	key := newTestRSAKey(t)
	config, _ := newTestAssertionConfig(t, key, "assertion-key")
	clock := newTestClock()

	assertion, err := newTestCache(clock).Get(context.Background(), config, testAssertionRequest)
	require.NoError(t, err)

	token := parseTestAssertion(t, assertion, &key.PublicKey)
	require.Equal(t, "RS256", token.Header["alg"])
	require.Equal(t, "assertion-key", token.Header["kid"])
	require.Equal(t, "client-authentication+jwt", token.Header["typ"])

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(assertion, ".")[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, map[string]any{
		"iss": "test-client-id",
		"sub": "test-client-id",
		"aud": "https://issuer.example.com", // a single string, never an array
		"iat": float64(clock.t.Unix()),
		"exp": float64(clock.t.Add(15 * time.Minute).Unix()),
	}, claims)
}

func TestClientAssertionIssuerOverride(t *testing.T) {
	key := newTestRSAKey(t)
	config, _ := newTestAssertionConfig(t, key, "assertion-key")
	config.Issuer = "https://auth.example.com"

	assertion, err := newTestCache(newTestClock()).Get(context.Background(), config, testAssertionRequest)
	require.NoError(t, err)

	claims := parseTestAssertion(t, assertion, &key.PublicKey).Claims.(jwt.MapClaims)
	require.Equal(t, "https://auth.example.com", claims["iss"])
	require.Equal(t, "test-client-id", claims["sub"])
}

func TestClientAssertionCacheLifetime(t *testing.T) {
	key := newTestRSAKey(t)
	config, signs := newTestAssertionConfig(t, key, "assertion-key")
	clock := newTestClock()
	cache := newTestCache(clock)
	ctx := context.Background()

	first, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)

	// reused while at least 5 minutes are left
	clock.advance(10 * time.Minute)
	again, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
	require.Equal(t, first, again)
	require.EqualValues(t, 1, signs.Load())

	// replaced once less than 5 minutes are left
	clock.advance(time.Second)
	refreshed, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
	require.NotEqual(t, first, refreshed)
	require.EqualValues(t, 2, signs.Load())

	claims := parseTestAssertion(t, refreshed, &key.PublicKey).Claims.(jwt.MapClaims)
	require.Equal(t, float64(clock.t.Unix()), claims["iat"])
}

func TestClientAssertionCacheEvictsExpiredEntries(t *testing.T) {
	config, _ := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
	clock := newTestClock()
	cache := newTestCache(clock)
	ctx := context.Background()

	stale := testAssertionRequest
	stale.ProviderID = "deleted-provider"
	_, err := cache.Get(ctx, config, stale)
	require.NoError(t, err)

	// not yet expired: kept when another entry is stored
	clock.advance(14 * time.Minute)
	_, err = cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
	require.Len(t, cache.entries, 2)

	// expired: dropped on the next store, while live entries stay
	clock.advance(time.Minute)
	other := testAssertionRequest
	other.ProviderID = "other-provider"
	_, err = cache.Get(ctx, config, other)
	require.NoError(t, err)
	require.Len(t, cache.entries, 2)
	require.NotContains(t, cache.entries, cache.cacheKey(config, stale))
	require.Contains(t, cache.entries, cache.cacheKey(config, testAssertionRequest))
}

func TestClientAssertionCacheKey(t *testing.T) {
	key := newTestRSAKey(t)
	config, signs := newTestAssertionConfig(t, key, "assertion-key")
	cache := newTestCache(newTestClock())
	ctx := context.Background()

	_, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)

	otherProvider := testAssertionRequest
	otherProvider.ProviderID = "another-provider"
	otherClient := testAssertionRequest
	otherClient.ClientID = "another-client"
	otherAudience := testAssertionRequest
	otherAudience.Audience = "https://other.example.com"
	for _, req := range []ClientAssertionRequest{otherProvider, otherClient, otherAudience} {
		_, err := cache.Get(ctx, config, req)
		require.NoError(t, err)
	}
	require.EqualValues(t, 4, signs.Load())

	// a rotated signing key or a changed issuer must not reuse the old assertion
	rotated, rotatedSigns := newTestAssertionConfig(t, newTestRSAKey(t), "rotated-key")
	_, err = cache.Get(ctx, rotated, testAssertionRequest)
	require.NoError(t, err)
	require.EqualValues(t, 1, rotatedSigns.Load())

	config.Issuer = "https://auth.example.com"
	_, err = cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
	require.EqualValues(t, 5, signs.Load())
}

func TestClientAssertionConcurrentRequestsSignOnce(t *testing.T) {
	key := newTestRSAKey(t)
	release := make(chan struct{})
	var signs atomic.Int32
	config := &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: newTestSigningJwk(t, key, "assertion-key"),
		SigningKey: func(context.Context) (any, error) {
			signs.Add(1)
			<-release
			return key, nil
		},
	}
	cache := newTestCache(newTestClock())

	const n = 20
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = cache.Get(context.Background(), config, testAssertionRequest)
		}()
	}
	// give the goroutines time to queue up behind the in-flight signing call;
	// any that arrive later are served from the cache, so the count holds
	// either way
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	require.EqualValues(t, 1, signs.Load())
	for i := range n {
		require.NoError(t, errs[i])
		require.Equal(t, results[0], results[i])
	}
}

func TestClientAssertionCanceledCallerDoesNotFailOthers(t *testing.T) {
	key := newTestRSAKey(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var signCtxErr error
	config := &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: newTestSigningJwk(t, key, "assertion-key"),
		SigningKey: func(ctx context.Context) (any, error) {
			close(started)
			<-release
			signCtxErr = ctx.Err()
			return key, nil
		},
	}
	cache := newTestCache(newTestClock())

	// the first caller starts the signing call, then its request is canceled
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.Get(firstCtx, config, testAssertionRequest)
		firstDone <- err
	}()
	<-started

	// a second caller joins the in-flight signing call
	secondDone := make(chan error, 1)
	go func() {
		_, err := cache.Get(context.Background(), config, testAssertionRequest)
		secondDone <- err
	}()
	time.Sleep(50 * time.Millisecond)

	cancelFirst()
	close(release)

	require.NoError(t, <-secondDone)
	require.NoError(t, <-firstDone)
	require.NoError(t, signCtxErr, "the shared signing call must not see the first caller's cancellation")
}

func TestClientAssertionDisabled(t *testing.T) {
	config, signs := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
	config.Enabled = false

	_, err := newTestCache(newTestClock()).Get(context.Background(), config, testAssertionRequest)
	require.ErrorIs(t, err, errClientAssertionNotConfigured)
	require.EqualValues(t, 0, signs.Load())
}

func TestClientAssertionInvalidate(t *testing.T) {
	key := newTestRSAKey(t)
	config, signs := newTestAssertionConfig(t, key, "assertion-key")
	clock := newTestClock()
	cache := newTestCache(clock)
	ctx := context.Background()

	first, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)

	other := testAssertionRequest
	other.ProviderID = "another-provider"
	_, err = cache.Get(ctx, config, other)
	require.NoError(t, err)

	cache.Invalidate(config, testAssertionRequest)
	clock.advance(time.Second)

	second, err := cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	// other providers keep their cached assertion
	_, err = cache.Get(ctx, config, other)
	require.NoError(t, err)
	require.EqualValues(t, 3, signs.Load())
}

func TestClientAssertionSigningErrors(t *testing.T) {
	cache := newTestCache(newTestClock())
	ctx := context.Background()

	_, err := cache.Get(ctx, &conf.ClientAssertionConfiguration{}, testAssertionRequest)
	require.ErrorIs(t, err, errClientAssertionNotConfigured)

	key := newTestRSAKey(t)
	sentinel := errors.New("signing unavailable")
	fail := true
	config := &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: newTestSigningJwk(t, key, "assertion-key"),
		SigningKey: func(context.Context) (any, error) {
			if fail {
				return nil, sentinel
			}
			return key, nil
		},
	}

	_, err = cache.Get(ctx, config, testAssertionRequest)
	require.ErrorIs(t, err, sentinel)

	// failures are not cached
	fail = false
	_, err = cache.Get(ctx, config, testAssertionRequest)
	require.NoError(t, err)
}

type fakeKMS struct {
	key   *rsa.PrivateKey
	calls atomic.Int32
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.calls.Add(1)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestClientAssertionKMSKey(t *testing.T) {
	key := newTestRSAKey(t)
	const arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"

	signingJwk := newTestSigningJwk(t, &key.PublicKey, "kms-key")
	require.NoError(t, signingJwk.Set("aws:kms:arn", arn))

	fake := &fakeKMS{key: key}
	config := &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: signingJwk,
		SigningKey: func(ctx context.Context) (any, error) {
			return &awskmsjwk.RS256Key{Ctx: ctx, KMS: fake, KeyID: arn, Raw: &key.PublicKey}, nil
		},
	}
	cache := newTestCache(newTestClock())

	assertion, err := cache.Get(context.Background(), config, testAssertionRequest)
	require.NoError(t, err)
	_, err = cache.Get(context.Background(), config, testAssertionRequest)
	require.NoError(t, err)
	require.EqualValues(t, 1, fake.calls.Load())

	token := parseTestAssertion(t, assertion, &key.PublicKey)
	require.Equal(t, "RS256", token.Header["alg"])
	require.Equal(t, "kms-key", token.Header["kid"])
}
