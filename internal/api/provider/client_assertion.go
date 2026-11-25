package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	// clientAssertionLifetime is how long a signed client assertion is valid.
	clientAssertionLifetime = 15 * time.Minute

	// clientAssertionRefreshBefore is how long before expiry a cached
	// assertion is replaced, so a request never goes out with an assertion
	// that is about to expire.
	clientAssertionRefreshBefore = 5 * time.Minute

	// clientAssertionSignTimeout bounds one signing call. The call is detached
	// from the caller's context (see Get), so this is what stops a stuck KMS
	// call from blocking every waiting request.
	clientAssertionSignTimeout = 10 * time.Second

	// clientAssertionType is the JWT typ header for client assertions.
	clientAssertionType = "client-authentication+jwt"

	// ClientAssertionTypeJWTBearer is the client_assertion_type value for
	// JWT client assertions (RFC 7523 section 2.2).
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- Not a secret value.
)

var (
	clientAssertionSignDuration = mustFloat64Histogram(
		"gotrue_client_assertion_sign_duration_seconds",
		"Time taken to sign a client assertion, including KMS calls",
	)
	clientAssertionSignErrors = observability.ObtainMetricCounter(
		"gotrue_client_assertion_sign_errors_total",
		"Number of client assertion signing errors, including KMS errors",
	)
	clientAssertionInvalidClient = observability.ObtainMetricCounter(
		"gotrue_client_assertion_invalid_client_total",
		"Number of invalid_client responses to token requests authenticated with a client assertion",
	)
)

func mustFloat64Histogram(name, desc string) metric.Float64Histogram {
	h, err := observability.Meter("gotrue").Float64Histogram(name, metric.WithDescription(desc), metric.WithUnit("s"))
	if err != nil {
		panic(err)
	}
	return h
}

var errClientAssertionNotConfigured = errors.New("client assertions are not enabled or no signing key is configured")

// ClientAssertionRequest identifies the provider an assertion is signed for.
type ClientAssertionRequest struct {
	ProviderID string
	ClientID   string
	// Audience is the aud claim: the provider's configured assertion
	// audience if set, otherwise its issuer.
	Audience string
}

type clientAssertionEntry struct {
	assertion string
	expiresAt time.Time
}

// ClientAssertionCache signs private_key_jwt client assertions (RFC 7523) and
// caches one per provider in memory, so the signing key (which may be in a
// KMS) is used about once every 10 minutes per provider instead of on every
// token request. Concurrent requests for the same provider share one signing
// call via singleflight.
//
// Assertions are bearer credentials: they must never be logged, stored, or
// included in errors.
type ClientAssertionCache struct {
	mu      sync.Mutex
	entries map[string]clientAssertionEntry
	sf      singleflight.Group
	now     func() time.Time // injectable for tests
}

// NewClientAssertionCache creates an empty cache.
func NewClientAssertionCache() *ClientAssertionCache {
	return &ClientAssertionCache{
		entries: make(map[string]clientAssertionEntry),
		now:     time.Now,
	}
}

// cacheKey includes the signing kid and issuer as well as the request, so a
// key rotation or issuer change on config reload stops serving old assertions.
func (c *ClientAssertionCache) cacheKey(config *conf.ClientAssertionConfiguration, req ClientAssertionRequest) string {
	return strings.Join([]string{
		req.ProviderID,
		req.ClientID,
		req.Audience,
		config.SigningJwk.KeyID(),
		config.Issuer,
	}, "\x00")
}

func (c *ClientAssertionCache) getFresh(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || c.now().Add(clientAssertionRefreshBefore).After(entry.expiresAt) {
		return "", false
	}
	return entry.assertion, true
}

// put stores entry and drops every expired entry. Keys that are no longer
// requested (deleted providers, rotated signing keys, changed audiences or
// issuers) are therefore removed within one assertion lifetime of the next
// signing. put runs about once per provider per refresh interval and the map
// holds one entry per provider, so the sweep is cheap.
func (c *ClientAssertionCache) put(key string, entry clientAssertionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = entry
}

// Get returns a client assertion for req, signing a new one if there is no
// cached assertion or it has less than clientAssertionRefreshBefore left.
func (c *ClientAssertionCache) Get(ctx context.Context, config *conf.ClientAssertionConfiguration, req ClientAssertionRequest) (string, error) {
	if !config.Enabled || config.SigningJwk == nil || config.SigningKey == nil {
		return "", errClientAssertionNotConfigured
	}

	key := c.cacheKey(config, req)
	if assertion, ok := c.getFresh(key); ok {
		return assertion, nil
	}

	val, err, _ := c.sf.Do(key, func() (any, error) {
		// another caller may have refreshed the entry while this one waited
		if assertion, ok := c.getFresh(key); ok {
			return assertion, nil
		}

		// every request waiting on this key shares the signing call, so it
		// must not fail because the first caller's request was canceled
		signCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clientAssertionSignTimeout)
		defer cancel()

		entry, err := c.sign(signCtx, config, req)
		if err != nil {
			return nil, err
		}
		c.put(key, entry)
		return entry.assertion, nil
	})
	if err != nil {
		return "", err
	}
	return val.(string), nil
}

// Invalidate drops the cached assertion for req, for example after the
// provider rejects it with invalid_client.
func (c *ClientAssertionCache) Invalidate(config *conf.ClientAssertionConfiguration, req ClientAssertionRequest) {
	if config.SigningJwk == nil {
		return
	}
	key := c.cacheKey(config, req)

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *ClientAssertionCache) sign(ctx context.Context, config *conf.ClientAssertionConfiguration, req ClientAssertionRequest) (clientAssertionEntry, error) {
	issuer := req.ClientID
	if config.Issuer != "" {
		issuer = config.Issuer
	}

	now := c.now()
	expiresAt := now.Add(clientAssertionLifetime)

	// MapClaims keeps aud a single string regardless of the package-level
	// jwt.MarshalSingleStringAsArray setting.
	token := jwt.NewWithClaims(conf.GetSigningAlg(config.SigningJwk), jwt.MapClaims{
		"iss": issuer,
		"sub": req.ClientID,
		"aud": req.Audience,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	})
	token.Header["typ"] = clientAssertionType
	token.Header["kid"] = config.SigningJwk.KeyID()

	started := time.Now()
	signed, err := signClientAssertion(ctx, config, token)
	result := "success"
	if err != nil {
		result = "error"
		clientAssertionSignErrors.Add(ctx, 1)
	}
	clientAssertionSignDuration.Record(ctx, time.Since(started).Seconds(),
		metric.WithAttributes(attribute.String("result", result)))
	if err != nil {
		return clientAssertionEntry{}, err
	}

	return clientAssertionEntry{
		assertion: signed,
		expiresAt: time.Unix(expiresAt.Unix(), 0),
	}, nil
}

func signClientAssertion(ctx context.Context, config *conf.ClientAssertionConfiguration, token *jwt.Token) (string, error) {
	signingKey, err := config.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	return token.SignedString(signingKey)
}

// clientAssertionSource binds a provider to the cache and the request it
// signs assertions for.
type clientAssertionSource struct {
	cache        *ClientAssertionCache
	config       *conf.ClientAssertionConfiguration
	req          ClientAssertionRequest
	providerName string
}

// UseClientAssertion makes the provider authenticate its token requests with
// a client assertion (private_key_jwt) instead of a client secret. The
// assertion goes in the form body only, never in a Basic auth header or the
// query string.
func (p *CustomOIDCProvider) UseClientAssertion(cache *ClientAssertionCache, config *conf.ClientAssertionConfiguration, req ClientAssertionRequest, providerName string) {
	p.config.ClientSecret = ""
	p.config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	p.clientAssertion = &clientAssertionSource{
		cache:        cache,
		config:       config,
		req:          req,
		providerName: providerName,
	}
}

func (p *CustomOIDCProvider) exchangeWithClientAssertion(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	src := p.clientAssertion

	assertion, err := src.cache.Get(ctx, src.config, src.req)
	if err != nil {
		// fail closed: without an assertion no token request is sent
		return nil, fmt.Errorf("unable to sign client assertion for provider %s: %w", src.providerName, err)
	}

	opts = append(opts,
		oauth2.SetAuthURLParam("client_assertion_type", ClientAssertionTypeJWTBearer),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	)
	token, err := p.config.Exchange(ctx, code, opts...)

	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && retrieveErr.ErrorCode == "invalid_client" {
		// sign a fresh assertion next time, in case this one is the problem
		src.cache.Invalidate(src.config, src.req)
		clientAssertionInvalidClient.Add(ctx, 1,
			metric.WithAttributes(attribute.String("provider", src.providerName)))
		logrus.WithFields(logrus.Fields{
			"provider":          src.providerName,
			"error_code":        retrieveErr.ErrorCode,
			"error_description": retrieveErr.ErrorDescription,
		}).Warn("token endpoint rejected the client assertion")
	}

	return token, err
}
