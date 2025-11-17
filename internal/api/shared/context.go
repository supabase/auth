package shared

import (
	"context"

	"github.com/supabase/auth/internal/models"
)

// ContextKey is the type for context keys to avoid collisions
type ContextKey string

func (c ContextKey) String() string {
	return "gotrue api context key " + string(c)
}

// Context keys used across packages
const (
	UserKey              ContextKey = "user"
	SessionKey           ContextKey = "session"
	OAuthServerClientKey ContextKey = "oauth_server_client"
)

// GetUser reads the user from the context - shared implementation
func GetUser(ctx context.Context) *models.User {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(UserKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.User)
}

// WithUser adds the user to the context - shared implementation
func WithUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, UserKey, u)
}

// GetSession reads the session from the context - shared implementation
func GetSession(ctx context.Context) *models.Session {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(SessionKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.Session)
}

// WithSession adds the session to the context - shared implementation
func WithSession(ctx context.Context, s *models.Session) context.Context {
	return context.WithValue(ctx, SessionKey, s)
}

// WithOAuthServerClient adds an OAuth server client to the context
func WithOAuthServerClient(ctx context.Context, client *models.OAuthServerClient) context.Context {
	return context.WithValue(ctx, OAuthServerClientKey, client)
}

// GetOAuthServerClient retrieves an OAuth server client from the context
func GetOAuthServerClient(ctx context.Context) *models.OAuthServerClient {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(OAuthServerClientKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.OAuthServerClient)
}
