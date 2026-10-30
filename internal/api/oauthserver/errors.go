package oauthserver

import (
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
)

// Token endpoint error codes per RFC 6749 Section 5.2, extending the set in authorize.go.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
const (
	oAuth2ErrorInvalidClient        = "invalid_client"
	oAuth2ErrorInvalidGrant         = "invalid_grant"
	oAuth2ErrorUnsupportedGrantType = "unsupported_grant_type"
)

// Only codes meaning the grant itself is dead may map to invalid_grant: that is the code telling a client to stop retrying and re-authorize the user.
var grantErrorCodes = map[string]string{
	apierrors.ErrorCodeRefreshTokenNotFound:    oAuth2ErrorInvalidGrant,
	apierrors.ErrorCodeRefreshTokenAlreadyUsed: oAuth2ErrorInvalidGrant,
	apierrors.ErrorCodeSessionNotFound:         oAuth2ErrorInvalidGrant,
	apierrors.ErrorCodeSessionExpired:          oAuth2ErrorInvalidGrant,
	apierrors.ErrorCodeUserBanned:              oAuth2ErrorInvalidGrant,

	apierrors.ErrorCodeValidationFailed: oAuth2ErrorInvalidRequest,
}

// oauthTokenError translates an error from the shared token service into an error response the token endpoint is allowed to return, per RFC 6749 Section 5.2 (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2). The service is shared with /auth/v1/token, whose clients parse the HTTPError shape, so the translation has to happen at this boundary.
func oauthTokenError(err error) error {
	switch e := err.(type) {
	case nil:
		return nil

	case *apierrors.OAuthError:
		return e

	case *apierrors.HTTPError:
		// A 409, 429 or 5xx says nothing about the grant, and every value in the spec's set asserts something about this request that retrying will not change.
		if e.HTTPStatus != http.StatusBadRequest {
			return e
		}

		code, ok := grantErrorCodes[e.ErrorCode]
		if !ok {
			code = oAuth2ErrorInvalidRequest
		}

		return apierrors.NewOAuthError(code, e.Message).WithInternalError(e)

	case interface{ Cause() error }:
		// storage.CommitWithError, used where the transaction must still commit.
		if cause := e.Cause(); cause != nil && cause != err {
			return oauthTokenError(cause)
		}
	}

	return err
}
