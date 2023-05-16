package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/storage"
)

// IdTokenGrantParams are the parameters the IdTokenGrant method accepts
type IdTokenGrantParams struct {
	IdToken  string `json:"id_token"`
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
}

func (p *IdTokenGrantParams) getVerifier(ctx context.Context, config *conf.GlobalConfiguration) (*oidc.IDTokenVerifier, error) {
	var provider *oidc.Provider
	var err error
	var oAuthProvider conf.OAuthProviderConfiguration
	var oAuthProviderClientId string
	switch p.Provider {
	case "apple":
		oAuthProvider = config.External.Apple
		oAuthProviderClientId = config.External.IosBundleId
		if oAuthProviderClientId == "" {
			oAuthProviderClientId = oAuthProvider.ClientID
		}
		provider, err = oidc.NewProvider(ctx, "https://appleid.apple.com")
	case "azure":
		oAuthProvider = config.External.Azure
		oAuthProviderClientId = oAuthProvider.ClientID
		url := oAuthProvider.URL
		if url == "" {
			url = "https://login.microsoftonline.com/common"
		}
		provider, err = oidc.NewProvider(ctx, url+"/v2.0")
	case "facebook":
		oAuthProvider = config.External.Facebook
		oAuthProviderClientId = oAuthProvider.ClientID
		provider, err = oidc.NewProvider(ctx, "https://www.facebook.com")
	case "google":
		oAuthProvider = config.External.Google
		oAuthProviderClientId = oAuthProvider.ClientID
		provider, err = oidc.NewProvider(ctx, "https://accounts.google.com")
	case "keycloak":
		oAuthProvider = config.External.Keycloak
		oAuthProviderClientId = oAuthProvider.ClientID
		provider, err = oidc.NewProvider(ctx, oAuthProvider.URL)
	default:
		return nil, fmt.Errorf("Provider %s doesn't support the id_token grant flow", p.Provider)
	}

	if err != nil {
		return nil, err
	}

	if !oAuthProvider.Enabled {
		return nil, badRequestError("Provider is not enabled")
	}

	return provider.Verifier(&oidc.Config{ClientID: oAuthProviderClientId}), nil
}

func (p *IdTokenGrantParams) getVerifierFromClientIDandIssuer(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	var provider *oidc.Provider
	var err error
	provider, err = oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer %s doesn't support the id_token grant flow", p.Issuer)
	}
	return provider.Verifier(&oidc.Config{ClientID: p.ClientID}), nil
}

// IdTokenGrant implements the id_token grant type flow
func (a *API) IdTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)
	config := a.config
	log := observability.GetLogEntry(r)

	params := &IdTokenGrantParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read id token grant params: %v", err)
	}

	if params.IdToken == "" {
		return oauthError("invalid request", "id_token required")
	}

	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return oauthError("invalid request", "provider or client_id and issuer required")
	}

	var verifier *oidc.IDTokenVerifier
	if params.Provider != "" {
		verifier, err = params.getVerifier(ctx, a.config)
	} else if params.ClientID != "" && params.Issuer != "" {
		log.WithField("issuer", params.Issuer).WithField("client_id", params.ClientID).Warn("Use of POST /token with issuer and client_id is deprecated for security reasons. Please switch to using the API with provider only!")

		for _, issuer := range a.config.External.AllowedIdTokenIssuers {
			if params.Issuer == issuer {
				verifier, err = params.getVerifierFromClientIDandIssuer(ctx)
				break
			}
		}
		if err != nil {
			return err
		}
		if verifier == nil {
			return badRequestError("Issuer not allowed")
		}
	} else {
		return badRequestError("%v", err)
	}
	if err != nil {
		return err
	}

	idToken, err := verifier.Verify(ctx, params.IdToken)
	if err != nil {
		return badRequestError("%v", err)
	}

	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	hashedNonce, ok := claims["nonce"]
	if (!ok && params.Nonce != "") || (ok && params.Nonce == "") {
		return oauthError("invalid request", "Passed nonce and nonce in id_token should either both exist or not.")
	}

	if ok && params.Nonce != "" {
		// verify nonce to mitigate replay attacks
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(params.Nonce)))
		if hash != hashedNonce.(string) {
			return oauthError("invalid nonce", "").WithInternalMessage("Possible abuse attempt: %v", r)
		}
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return oauthError("invalid request", "missing sub claim in id_token")
	}

	email, ok := claims["email"].(string)
	if !ok {
		email = ""
	}

	var user *models.User
	var grantParams models.GrantParams
	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		var identity *models.Identity

		if identity, terr = models.FindIdentityByIdAndProvider(tx, sub, params.Provider); terr != nil {
			// create new identity & user if identity is not found
			if models.IsNotFoundError(terr) {
				if config.DisableSignup {
					return forbiddenError("Signups not allowed for this instance")
				}
				aud := a.requestAud(ctx, r)
				signupParams := &SignupParams{
					Provider: params.Provider,
					Email:    email,
					Aud:      aud,
					Data:     claims,
				}

				user, terr = a.signupNewUser(ctx, tx, signupParams, false /* <- isSSOUser */)
				if terr != nil {
					return terr
				}
				if _, terr = a.createNewIdentity(tx, user, params.Provider, claims); terr != nil {
					return terr
				}
			} else {
				return terr
			}
		} else {
			user, terr = models.FindUserByID(tx, identity.UserID)
			if terr != nil {
				return terr
			}
			if email != "" {
				identity.IdentityData["email"] = email
			}
			if user.IsBanned() {
				return oauthError("invalid_grant", "invalid id token grant")
			}
			if terr = tx.UpdateOnly(identity, "identity_data", "last_sign_in_at"); terr != nil {
				return terr
			}
			if terr = user.UpdateAppMetaDataProviders(tx); terr != nil {
				return terr
			}
		}

		if !user.IsConfirmed() {
			isEmailVerified := false
			emailVerified, ok := claims["email_verified"]
			if ok {
				isEmailVerified = getEmailVerified(emailVerified)
			}
			if (!ok || !isEmailVerified) && !config.Mailer.Autoconfirm {

				mailer := a.Mailer(ctx)
				referrer := a.getReferrer(r)
				externalURL := getExternalHost(ctx)
				if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, externalURL, config.Mailer.OtpLength, models.ImplicitFlow); terr != nil {
					return internalServerError("Error sending confirmation mail").WithInternalError(terr)
				}
				return unauthorizedError("Error unverified email")
			}

			if terr := models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
				"provider": params.Provider,
			}); terr != nil {
				return terr
			}

			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
				return terr
			}

			if terr = user.Confirm(tx); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		} else {
			if terr := models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
				"provider": params.Provider,
			}); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, config); terr != nil {
				return terr
			}
		}
		token, terr = a.issueRefreshToken(ctx, tx, user, models.OAuth, grantParams)

		if terr != nil {
			return oauthError("server_error", terr.Error())
		}
		return nil
	})

	if err != nil {
		return err
	}

	if err := a.setCookieTokens(config, token, false, w); err != nil {
		return internalServerError("Failed to set JWT cookie. %s", err)
	}

	metering.RecordLogin("id_token", user.ID)
	return sendJSON(w, http.StatusOK, token)
}
