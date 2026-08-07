package shared

import (
	"context"

	"github.com/supabase/auth/internal/models"
)

// ContextKey is the type for context keys to avoid collisions
type ContextKey[T any] string

func (c ContextKey[T]) String() string {
	return "gotrue api context key " + string(c)
}

func (key ContextKey[T]) Get(ctx context.Context) T {
	var zero T
	if ctx == nil {
		return zero
	}
	obj := ctx.Value(key)
	if obj == nil {
		return zero
	}
	return obj.(T)
}

func (key ContextKey[T]) With(ctx context.Context, t T) context.Context {
	return context.WithValue(ctx, key, t)
}

// Context keys used across packages
const (
	UserKey              ContextKey[*models.User]              = "user"
	SessionKey           ContextKey[*models.Session]           = "session"
	OAuthServerClientKey ContextKey[*models.OAuthServerClient] = "oauth_server_client"
	SSOProviderKey       ContextKey[*models.SSOProvider]       = "sso_provider"
)

// GetUser reads the user from the context - shared implementation
func GetUser(ctx context.Context) *models.User {
	return UserKey.Get(ctx)
}

// WithUser adds the user to the context - shared implementation
func WithUser(ctx context.Context, u *models.User) context.Context {
	return UserKey.With(ctx, u)
}

// GetSession reads the session from the context - shared implementation
func GetSession(ctx context.Context) *models.Session {
	return SessionKey.Get(ctx)
}

// WithSession adds the session to the context - shared implementation
func WithSession(ctx context.Context, s *models.Session) context.Context {
	return SessionKey.With(ctx, s)
}

// WithOAuthServerClient adds an OAuth server client to the context
func WithOAuthServerClient(ctx context.Context, client *models.OAuthServerClient) context.Context {
	return OAuthServerClientKey.With(ctx, client)
}

// GetOAuthServerClient retrieves an OAuth server client from the context
func GetOAuthServerClient(ctx context.Context) *models.OAuthServerClient {
	return OAuthServerClientKey.Get(ctx)
}

func GetSSOProvider(ctx context.Context) *models.SSOProvider {
	return SSOProviderKey.Get(ctx)
}

func WithSSOProvider(ctx context.Context, s *models.SSOProvider) context.Context {
	return SSOProviderKey.With(ctx, s)
}
