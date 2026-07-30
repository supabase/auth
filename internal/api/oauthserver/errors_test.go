package oauthserver

import (
	"testing"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/storage"
)

func TestOAuthTokenError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		// the expected OAuth error code, empty when the error should pass through untranslated
		expected string
		// the expected error_description, when it needs asserting
		expectedDescription string
		// the status an untranslated error must keep
		expectedStatus int
	}{
		{
			name:     "refresh token not found should return invalid_grant",
			err:      apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenNotFound, "Invalid Refresh Token: Refresh Token Not Found"),
			expected: "invalid_grant",
		},
		{
			name:     "session expired should return invalid_grant",
			err:      apierrors.NewBadRequestError(apierrors.ErrorCodeSessionExpired, "Invalid Refresh Token: Session Expired"),
			expected: "invalid_grant",
		},
		{
			name:     "refresh token reuse wrapped in CommitWithError should return invalid_grant",
			err:      storage.NewCommitWithError(apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used")),
			expected: "invalid_grant",
		},
		{
			name:                "the internal message should not reach the client",
			err:                 apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used").WithInternalMessage("Possible abuse attempt: %v", "6a3c1f0e"),
			expected:            "invalid_grant",
			expectedDescription: "Invalid Refresh Token: Already Used",
		},
		{
			name:     "validation failure should return invalid_request",
			err:      apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid Refresh Token: Not Issued By This Server"),
			expected: "invalid_request",
		},
		{
			name:     "unrecognized error code should return invalid_request, not invalid_grant",
			err:      apierrors.NewBadRequestError("some_future_error_code", "Something new"),
			expected: "invalid_request",
		},
		{
			name:           "concurrent refresh should pass through as a 409",
			err:            apierrors.NewConflictError("Too many concurrent token refresh requests on the same session or refresh token"),
			expectedStatus: 409,
		},
		{
			name:           "internal failure should pass through as a 500",
			err:            apierrors.NewInternalServerError("error generating jwt token"),
			expectedStatus: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oauthTokenError(tt.err)

			if tt.expected == "" {
				httpErr, ok := result.(*apierrors.HTTPError)
				if !ok {
					t.Fatalf("oauthTokenError() = %T, expected the error to pass through as *apierrors.HTTPError", result)
				}
				if httpErr.HTTPStatus != tt.expectedStatus {
					t.Errorf("oauthTokenError() status = %v, expected %v", httpErr.HTTPStatus, tt.expectedStatus)
				}
				return
			}

			oauthErr, ok := result.(*apierrors.OAuthError)
			if !ok {
				t.Fatalf("oauthTokenError() = %T, expected *apierrors.OAuthError", result)
			}
			if oauthErr.Err != tt.expected {
				t.Errorf("oauthTokenError() error = %v, expected %v", oauthErr.Err, tt.expected)
			}
			if tt.expectedDescription != "" && oauthErr.Description != tt.expectedDescription {
				t.Errorf("oauthTokenError() error_description = %v, expected %v", oauthErr.Description, tt.expectedDescription)
			}
		})
	}
}
