package api

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// AccessTokenGrantParams are the parameters the AccessTokenGrant method accepts
type AccessTokenGrantParams struct {
	Provider    string `json:"provider"`
	AccessToken string `json:"access_token"`
}

// AccessTokenGrant implements the access_token grant type flow, which allows
// signing in with a provider issued OAuth access token instead of an OIDC id
// token.
//
// It exists mainly for native Facebook logins on Android: the Facebook SDK
// reliably returns a classic Graph access token on every login, but only mints
// an OIDC id token (AuthenticationToken) on the first authorization, which
// makes the id_token grant unusable for repeat logins without falling back to
// the browser flow.
func (a *API) AccessTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)

	params := &AccessTokenGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.AccessToken == "" {
		return apierrors.NewOAuthError("invalid request", "access_token required")
	}

	if params.Provider == "" {
		return apierrors.NewOAuthError("invalid request", "provider required")
	}

	oauthProvider, pConfig, err := a.OAuthProvider(ctx, params.Provider)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeOAuthProviderNotSupported, "Unsupported provider: %+v", err).WithInternalError(err)
	}

	if !pConfig.Enabled {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeProviderDisabled, "Provider (%q) is not enabled", params.Provider)
	}

	// Verifying that the access token was issued for this app is provider
	// specific, so the grant is only available to providers that opt in.
	verifier, ok := oauthProvider.(provider.AccessTokenVerifier)
	if !ok {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "access_token grant is not supported for the %q provider", params.Provider)
	}

	if err := verifier.VerifyAccessToken(ctx, params.AccessToken); err != nil {
		return apierrors.NewOAuthError("invalid request", "Invalid access token").WithInternalError(err)
	}

	userData, err := oauthProvider.GetUserData(ctx, &oauth2.Token{AccessToken: params.AccessToken})
	if err != nil {
		return apierrors.NewOAuthError("invalid request", "Unable to fetch user data with the provided access token").WithInternalError(err)
	}

	userData.Metadata.EmailVerified = false
	for _, email := range userData.Emails {
		if email.Primary {
			userData.Metadata.Email = email.Email
			userData.Metadata.EmailVerified = email.Verified
			break
		} else {
			userData.Metadata.Email = email.Email
			userData.Metadata.EmailVerified = email.Verified
		}
	}

	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)

	if err := a.triggerBeforeUserCreatedExternal(r, db, userData, params.Provider); err != nil {
		return err
	}

	var createdUser bool
	var token *AccessTokenResponse
	var user *models.User
	if err := db.Transaction(func(tx *storage.Connection) error {
		var terr error

		var decision models.AccountLinkingDecision
		decision, user, terr = a.createAccountFromExternalIdentity(tx, r, userData, params.Provider, pConfig.EmailOptional)
		if terr != nil {
			return terr
		}
		createdUser = decision == models.CreateAccount

		token, terr = a.issueRefreshToken(r, w.Header(), tx, user, models.OAuth, grantParams)
		if terr != nil {
			return terr
		}

		return nil
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
	if createdUser {
		if err := a.triggerAfterUserCreated(r, db, user); err != nil {
			return err
		}
	}

	metering.RecordLogin(metering.LoginTypeOAuth, token.User.ID, &metering.LoginData{
		Provider: params.Provider,
	})

	return sendJSON(w, http.StatusOK, token)
}
