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
