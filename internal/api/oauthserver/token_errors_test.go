package oauthserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
)

func TestMapRefreshTokenGrantError(t *testing.T) {
	t.Run("refresh token not found maps to invalid_grant", func(t *testing.T) {
		err := mapRefreshTokenGrantError(apierrors.NewBadRequestError(
			apierrors.ErrorCodeRefreshTokenNotFound,
			"Invalid Refresh Token: Refresh Token Not Found",
		))
		oauthErr, ok := err.(*apierrors.OAuthError)
		require.True(t, ok)
		require.Equal(t, "invalid_grant", oauthErr.Err)
		require.Equal(t, "Refresh token is invalid or expired.", oauthErr.Description)
	})

	t.Run("session expired maps to invalid_grant", func(t *testing.T) {
		err := mapRefreshTokenGrantError(apierrors.NewBadRequestError(
			apierrors.ErrorCodeSessionExpired,
			"Invalid Refresh Token: Session Expired",
		))
		oauthErr, ok := err.(*apierrors.OAuthError)
		require.True(t, ok)
		require.Equal(t, "invalid_grant", oauthErr.Err)
	})

	t.Run("user banned maps to access_denied", func(t *testing.T) {
		err := mapRefreshTokenGrantError(apierrors.NewBadRequestError(
			apierrors.ErrorCodeUserBanned,
			"Invalid Refresh Token: User Banned",
		))
		oauthErr, ok := err.(*apierrors.OAuthError)
		require.True(t, ok)
		require.Equal(t, "access_denied", oauthErr.Err)
	})

	t.Run("internal errors pass through", func(t *testing.T) {
		internal := apierrors.NewInternalServerError("database unavailable")
		require.Equal(t, internal, mapRefreshTokenGrantError(internal))
	})

	t.Run("oauth errors pass through", func(t *testing.T) {
		oauth := apierrors.NewOAuthError("invalid_client", "Client authentication required")
		require.Equal(t, oauth, mapRefreshTokenGrantError(oauth))
	})
}
