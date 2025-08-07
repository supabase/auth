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
	UserKey ContextKey = "user"
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
