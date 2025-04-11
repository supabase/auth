package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// IdTokenGrantParams are the parameters the IdTokenGrant method accepts
type IdTokenGrantParams struct {
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	Nonce       string `json:"nonce"`
	Provider    string `json:"provider"`
	ClientID    string `json:"client_id"`
	Issuer      string `json:"issuer"`
}

func (p *IdTokenGrantParams) getProvider(ctx context.Context, config *conf.GlobalConfiguration, r *http.Request) (*oidc.Provider, bool, string, []string, error) {
	log := observability.GetLogEntry(r).Entry

	var cfg *conf.OAuthProviderConfiguration
	var issuer string
	var providerType string
	var acceptableClientIDs []string

	switch true {
	case p.Provider == "apple" || p.Issuer == provider.IssuerApple:
		cfg = &config.External.Apple
		providerType = "apple"
		issuer = provider.IssuerApple
		acceptableClientIDs = append(acceptableClientIDs, config.External.Apple.ClientID...)

		if config.External.IosBundleId != "" {
			acceptableClientIDs = append(acceptableClientIDs, config.External.IosBundleId)
		}

	case p.Provider == "google" || p.Issuer == provider.IssuerGoogle:
		cfg = &config.External.Google
		providerType = "google"
		issuer = provider.IssuerGoogle
		acceptableClientIDs = append(acceptableClientIDs, config.External.Google.ClientID...)

	case p.Provider == "azure" || provider.IsAzureIssuer(p.Issuer):
		issuer = p.Issuer
		if issuer == "" || !provider.IsAzureIssuer(issuer) {
			detectedIssuer, err := provider.DetectAzureIDTokenIssuer(ctx, p.IdToken)
			if err != nil {
				return nil, false, "", nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Unable to detect issuer in ID token for Azure provider").WithInternalError(err)
			}
			issuer = detectedIssuer
		}
		cfg = &config.External.Azure
		providerType = "azure"
		acceptableClientIDs = append(acceptableClientIDs, config.External.Azure.ClientID...)

	case p.Provider == "facebook" || p.Issuer == provider.IssuerFacebook:
		cfg = &config.External.Facebook
		providerType = "facebook"
		issuer = provider.IssuerFacebook
		acceptableClientIDs = append(acceptableClientIDs, config.External.Facebook.ClientID...)

	case p.Provider == "keycloak" || (config.External.Keycloak.Enabled && config.External.Keycloak.URL != "" && p.Issuer == config.External.Keycloak.URL):
		cfg = &config.External.Keycloak
		providerType = "keycloak"
		issuer = config.External.Keycloak.URL
		acceptableClientIDs = append(acceptableClientIDs, config.External.Keycloak.ClientID...)

	case p.Provider == "kakao" || p.Issuer == provider.IssuerKakao:
		cfg = &config.External.Kakao
		providerType = "kakao"
		issuer = provider.IssuerKakao
		acceptableClientIDs = append(acceptableClientIDs, config.External.Kakao.ClientID...)

	case p.Provider == "vercel_marketplace" || p.Issuer == provider.IssuerVercelMarketplace:
		cfg = &config.External.VercelMarketplace
		providerType = "vercel_marketplace"
		issuer = provider.IssuerVercelMarketplace
		acceptableClientIDs = append(acceptableClientIDs, config.External.VercelMarketplace.ClientID...)

	default:
		log.WithField("issuer", p.Issuer).WithField("client_id", p.ClientID).Warn("Use of POST /token with arbitrary issuer and client_id is deprecated for security reasons. Please switch to using the API with provider only!")

		allowed := false
		for _, allowedIssuer := range config.External.AllowedIdTokenIssuers {
			if p.Issuer == allowedIssuer {
				allowed = true
				providerType = allowedIssuer
				acceptableClientIDs = []string{p.ClientID}
				issuer = allowedIssuer
				break
			}
		}

		if !allowed {
			return nil, false, "", nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, fmt.Sprintf("Custom OIDC provider %q not allowed", p.Provider))
		}

		cfg = &conf.OAuthProviderConfiguration{
			Enabled:        true,
			SkipNonceCheck: false,
		}
	}

	if !cfg.Enabled {
		return nil, false, "", nil, apierrors.NewBadRequestError(apierrors.ErrorCodeProviderDisabled, fmt.Sprintf("Provider (issuer %q) is not enabled", issuer))
	}

	oidcProvider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, false, "", nil, err
	}

	return oidcProvider, cfg.SkipNonceCheck, providerType, acceptableClientIDs, nil
}

// IdTokenGrant implements the id_token grant type flow
func (a *API) IdTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	log := observability.GetLogEntry(r).Entry

	db := a.db.WithContext(ctx)
	config := a.config

	params := &IdTokenGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.IdToken == "" {
		return apierrors.NewOAuthError("invalid request", "id_token required")
	}

	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return apierrors.NewOAuthError("invalid request", "provider or client_id and issuer required")
	}

	oidcProvider, skipNonceCheck, providerType, acceptableClientIDs, err := params.getProvider(ctx, config, r)
	if err != nil {
		return err
	}

	idToken, userData, err := provider.ParseIDToken(ctx, oidcProvider, nil, params.IdToken, provider.ParseIDTokenOptions{
		SkipAccessTokenCheck: params.AccessToken == "",
		AccessToken:          params.AccessToken,
	})
	if err != nil {
		return apierrors.NewOAuthError("invalid request", "Bad ID token").WithInternalError(err)
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

	if idToken.Subject == "" {
		return apierrors.NewOAuthError("invalid request", "Missing sub claim in id_token")
	}

	correctAudience := false
	for _, clientID := range acceptableClientIDs {
		if clientID == "" {
			continue
		}

		for _, aud := range idToken.Audience {
			if aud == clientID {
				correctAudience = true
				break
			}
		}

		if correctAudience {
			break
		}
	}

	if !correctAudience {
		return apierrors.NewOAuthError("invalid request", fmt.Sprintf("Unacceptable audience in id_token: %v", idToken.Audience))
	}

	if !skipNonceCheck {
		tokenHasNonce := idToken.Nonce != ""
		paramsHasNonce := params.Nonce != ""

		if tokenHasNonce != paramsHasNonce {
			return apierrors.NewOAuthError("invalid request", "Passed nonce and nonce in id_token should either both exist or not.")
		} else if tokenHasNonce && paramsHasNonce {
			// verify nonce to mitigate replay attacks
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(params.Nonce)))
			if hash != idToken.Nonce {
				return apierrors.NewOAuthError("invalid nonce", "Nonces mismatch")
			}
		}
	}

	if params.AccessToken == "" {
		if idToken.AccessTokenHash != "" {
			log.Warn("ID token has a at_hash claim, but no access_token parameter was provided. In future versions, access_token will be mandatory as it's security best practice.")
		}
	} else {
		if idToken.AccessTokenHash == "" {
			log.Info("ID token does not have a at_hash claim, access_token parameter is unused.")
		}
	}

	var token *AccessTokenResponse
	var grantParams models.GrantParams

	grantParams.FillGrantParams(r)

	if err := db.Transaction(func(tx *storage.Connection) error {
		var user *models.User
		var terr error

		user, terr = a.createAccountFromExternalIdentity(tx, r, userData, providerType)
		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(r, tx, user, models.OAuth, grantParams)
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

	return sendJSON(w, http.StatusOK, token)
}
