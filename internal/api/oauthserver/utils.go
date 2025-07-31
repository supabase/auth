package oauthserver

import (
	"context"

	"github.com/supabase/auth/internal/models"
)

// Context keys for OAuth server functionality
type contextKey string

const (
	oauthServerClientKey contextKey = "oauth_server_client"
)

// WithOAuthServerClient adds an OAuth server client to the context
func WithOAuthServerClient(ctx context.Context, client *models.OAuthServerClient) context.Context {
	return context.WithValue(ctx, oauthServerClientKey, client)
}

// GetOAuthServerClient retrieves an OAuth server client from the context
func GetOAuthServerClient(ctx context.Context) *models.OAuthServerClient {
	obj := ctx.Value(oauthServerClientKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.OAuthServerClient)
}
