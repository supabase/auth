package oauthserver

import (
	"github.com/supabase/auth/internal/api/apierrors"
)

func mapRefreshTokenGrantError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := err.(*apierrors.OAuthError); ok {
		return err
	}

	httpErr, ok := err.(*apierrors.HTTPError)
	if !ok {
		return err
	}

	switch httpErr.ErrorCode {
	case apierrors.ErrorCodeRefreshTokenNotFound,
		apierrors.ErrorCodeRefreshTokenAlreadyUsed,
		apierrors.ErrorCodeSessionNotFound,
		apierrors.ErrorCodeSessionExpired:
		return apierrors.NewOAuthError("invalid_grant", "Refresh token is invalid or expired.")
	case apierrors.ErrorCodeUserBanned:
		return apierrors.NewOAuthError("access_denied", "User is not permitted to access this resource.")
	default:
		return err
	}
}
