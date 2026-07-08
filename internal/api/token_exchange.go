package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// TokenExchangeGrantType is the RFC 8693 OAuth 2.0 Token Exchange grant type.
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //#nosec G101 -- Not a credential, an RFC 8693 grant-type URI.

// FacebookAccessTokenType is the subject_token_type URI identifying a Facebook
// access token for the token-exchange grant.
const FacebookAccessTokenType = "https://supabase.com/auth/token-type/facebook-access-token" //#nosec G101 -- Not a credential, a token-type URI.

// subjectTokenTypeProviders maps each supported subject_token_type to the
// provider whose access token it carries. The provider is inferred from the
// token type rather than passed separately, so a new provider opts in by
// registering its own token type here.
var subjectTokenTypeProviders = map[string]string{
	FacebookAccessTokenType: "facebook",
}

// TokenExchangeGrantParams are the parameters the TokenExchangeGrant method accepts.
type TokenExchangeGrantParams struct {
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	LinkIdentity     bool   `json:"link_identity"`
}

// TokenExchangeGrant implements the RFC 8693 token-exchange grant. It lets a
// client sign in with a provider-issued access token instead of an OIDC id
// token.
//
// It exists for native Facebook logins on Android: Facebook only mints an OIDC
// id token (with the email claims) on the first authorization, so signup keeps
// going through the id_token grant. On every subsequent login Facebook returns
// only a classic access token, which carries no profile claims. This grant
// verifies that token belongs to this app, reads the provider subject from it,
// and signs in the existing identity, so it does not create accounts.
//
// When link_identity is set and a valid user access token is provided in the
// Authorization header, the provider identity is linked to that user instead of
// signing in an existing identity.
func (a *API) TokenExchangeGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)

	params := &TokenExchangeGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.SubjectToken == "" {
		return apierrors.NewOAuthError("invalid_request", "subject_token required")
	}

	// The provider is inferred from the subject_token_type, so the client never
	// sends it separately. The mapped value is already the lower-cased provider
	// name stored on the identity, so no normalization is needed.
	providerType, ok := subjectTokenTypeProviders[params.SubjectTokenType]
	if !ok {
		return apierrors.NewOAuthError("invalid_request", fmt.Sprintf("unsupported subject_token_type %q", params.SubjectTokenType))
	}

	// When linking, the caller must present a valid user access token; the
	// verified provider identity is attached to that user instead of signing in
	// an existing identity.
	var targetUser *models.User
	if params.LinkIdentity {
		if r.Header.Get("Authorization") == "" {
			return apierrors.NewOAuthError("invalid_request", "Linking requires a valid user access token in Authorization")
		}

		requireAuthCtx, err := a.requireAuthentication(w, r)
		if err != nil {
			return err
		}

		targetUser = getUser(requireAuthCtx)
		if targetUser == nil {
			return apierrors.NewOAuthError("invalid_request", "Linking requires a valid user authentication")
		}

		if targetUser.IsBanned() {
			return apierrors.NewOAuthError("invalid_grant", "User is banned")
		}

		// set it so linkIdentityToUser works below
		ctx = withTargetUser(ctx, targetUser)
	}

	oauthProvider, pConfig, err := a.OAuthProvider(ctx, providerType)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeOAuthProviderNotSupported, "Unsupported provider: %q", providerType).WithInternalError(err)
	}

	if !pConfig.Enabled {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeProviderDisabled, "Provider (%q) is not enabled", providerType)
	}

	// Verifying that the access token was issued for this app is provider
	// specific, so the grant is only available to providers that opt in.
	verifier, ok := oauthProvider.(provider.AccessTokenVerifier)
	if !ok {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "token-exchange grant is not supported for the %q provider", providerType)
	}

	subject, err := verifier.VerifyAccessToken(ctx, params.SubjectToken)
	if err != nil {
		return apierrors.NewOAuthError("invalid_request", "Invalid subject_token").WithInternalError(err)
	}

	// The provider access token carries no profile claims, so this grant only
	// signs in an identity that already exists (created on the first login via
	// the id_token grant). A missing identity means the user must sign up first,
	// but the error stays generic to avoid leaking whether an account exists.
	var user *models.User
	if !params.LinkIdentity {
		identity, err := models.FindIdentityByIdAndProvider(db, subject, providerType)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewOAuthError("invalid_request", "Invalid subject_token").WithInternalError(err)
			}
			return apierrors.NewInternalServerError("Database error finding identity").WithInternalError(err)
		}

		user, err = models.FindUserByID(db, identity.UserID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewOAuthError("invalid_request", "No user found for this identity")
			}
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}

		if user.IsBanned() {
			return apierrors.NewOAuthError("invalid_request", "Invalid subject_token")
		}

		// Don't hand out a session to an unconfirmed user unless the instance
		// allows unverified email sign-ins, matching the other sign-in paths.
		// The error stays generic to avoid leaking account state.
		if !user.IsConfirmed() && !a.config.Mailer.AllowUnverifiedEmailSignIns {
			return apierrors.NewOAuthError("invalid_request", "Invalid subject_token")
		}
	}

	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)

	// userData for the link path carries only the provider subject; the access
	// token exposes no profile claims.
	userData := &provider.UserProvidedData{Metadata: &provider.Claims{Subject: subject}}

	var token *AccessTokenResponse
	if err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.LinkIdentity {
			user, terr = a.linkIdentityToUser(r, ctx, tx, userData, providerType)
			if terr != nil {
				return terr
			}
		}
		if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": providerType,
		}); terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(r, w.Header(), tx, user, models.OAuth, grantParams)
		return terr
	}); err != nil {
		switch err.(type) {
		case *storage.CommitWithError:
			return err
		case *HTTPError:
			return err
		default:
			return apierrors.NewOAuthError("server_error", "Internal Server Error").WithInternalError(err)
		}
	}

	metering.RecordLogin(metering.LoginTypeTokenExchange, token.User.ID, &metering.LoginData{
		Provider: providerType,
	})

	return sendJSON(w, http.StatusOK, token)
}
