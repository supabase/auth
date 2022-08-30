package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// GoTrueClaims is a struct thats used for JWT claims
type GoTrueClaims struct {
	jwt.StandardClaims
	Email                         string                 `json:"email"`
	Phone                         string                 `json:"phone"`
	AppMetaData                   map[string]interface{} `json:"app_metadata"`
	UserMetaData                  map[string]interface{} `json:"user_metadata"`
	Role                          string                 `json:"role"`
	AuthenticatorAssuranceLevel   string                 `json:"aal"`
	AuthenticationMethodReference []AMREntry             `json:"amr"`
	SessionId                     string                 `json:"session_id"`
}

// AccessTokenResponse represents an OAuth2 success response
type AccessTokenResponse struct {
	Token        string       `json:"access_token"`
	TokenType    string       `json:"token_type"` // Bearer
	ExpiresIn    int          `json:"expires_in"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

// PasswordGrantParams are the parameters the ResourceOwnerPasswordGrant method accepts
type PasswordGrantParams struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

// RefreshTokenGrantParams are the parameters the RefreshTokenGrant method accepts
type RefreshTokenGrantParams struct {
	RefreshToken string `json:"refresh_token"`
}

// AMREntry represents a method that a user has logged in together with the corresponding time
type AMREntry struct {
	Method    string    `json:"method"`
	Timestamp time.Time `json:"timestamp"`
}

// IdTokenGrantParams are the parameters the IdTokenGrant method accepts
type IdTokenGrantParams struct {
	IdToken  string `json:"id_token"`
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
}

const useCookieHeader = "x-use-cookie"
const InvalidLoginMessage = "Invalid login credentials"

func (p *IdTokenGrantParams) getVerifier(ctx context.Context, config *conf.GlobalConfiguration) (*oidc.IDTokenVerifier, error) {
	var provider *oidc.Provider
	var err error
	var oAuthProvider conf.OAuthProviderConfiguration
	var oAuthProviderClientId string
	switch p.Provider {
	case "apple":
		oAuthProvider = config.External.Apple
		oAuthProviderClientId = config.External.IosBundleId
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
		return nil, fmt.Errorf("Issuer %s doesn't support the id_token grant flow", p.Issuer)
	}
	return provider.Verifier(&oidc.Config{ClientID: p.ClientID}), nil
}

func getEmailVerified(v interface{}) bool {
	var emailVerified bool
	var err error
	switch v.(type) {
	case string:
		emailVerified, err = strconv.ParseBool(v.(string))
	case bool:
		emailVerified = v.(bool)
	default:
		emailVerified = false
	}
	if err != nil {
		return false
	}
	return emailVerified
}

// Token is the endpoint for OAuth access token requests
func (a *API) Token(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "password":
		return a.ResourceOwnerPasswordGrant(ctx, w, r)
	case "refresh_token":
		return a.RefreshTokenGrant(ctx, w, r)
	case "id_token":
		return a.IdTokenGrant(ctx, w, r)
	default:
		return oauthError("unsupported_grant_type", "")
	}
}

// ResourceOwnerPasswordGrant implements the password grant type flow
func (a *API) ResourceOwnerPasswordGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	params := &PasswordGrantParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read password grant params: %v", err)
	}

	aud := a.requestAud(ctx, r)
	config := a.config

	if params.Email != "" && params.Phone != "" {
		return unprocessableEntityError("Only an email address or phone number should be provided on login.")
	}
	var user *models.User
	var provider string
	if params.Email != "" {
		provider = "email"
		if !config.External.Email.Enabled {
			return badRequestError("Email logins are disabled")
		}
		user, err = models.FindUserByEmailAndAudience(a.db, params.Email, aud)
	} else if params.Phone != "" {
		provider = "phone"
		if !config.External.Phone.Enabled {
			return badRequestError("Phone logins are disabled")
		}
		params.Phone = a.formatPhoneNumber(params.Phone)
		user, err = models.FindUserByPhoneAndAudience(a.db, params.Phone, aud)
	} else {
		return oauthError("invalid_grant", InvalidLoginMessage)
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return oauthError("invalid_grant", InvalidLoginMessage)
		}
		return internalServerError("Database error querying schema").WithInternalError(err)
	}

	if user.IsBanned() || !user.Authenticate(params.Password) {
		return oauthError("invalid_grant", InvalidLoginMessage)
	}

	if params.Email != "" && !user.IsConfirmed() {
		return oauthError("invalid_grant", "Email not confirmed")
	} else if params.Phone != "" && !user.IsPhoneConfirmed() {
		return oauthError("invalid_grant", "Phone not confirmed")
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": provider,
		}); terr != nil {
			return terr
		}
		if terr = triggerEventHooks(ctx, tx, LoginEvent, user, config); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("password", user.ID)
	return sendJSON(w, http.StatusOK, token)
}

// RefreshTokenGrant implements the refresh_token grant type flow
func (a *API) RefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	config := a.config

	params := &RefreshTokenGrantParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read refresh token grant params: %v", err)
	}

	if params.RefreshToken == "" {
		return oauthError("invalid_request", "refresh_token required")
	}

	user, token, err := models.FindUserWithRefreshToken(a.db, params.RefreshToken)
	if err != nil {
		if models.IsNotFoundError(err) {
			return oauthError("invalid_grant", "Invalid Refresh Token")
		}
		return internalServerError(err.Error())
	}

	if user.IsBanned() {
		return oauthError("invalid_grant", "Invalid Refresh Token")
	}

	var newToken *models.RefreshToken
	if token.Revoked {
		a.clearCookieTokens(config, w)
		err = a.db.Transaction(func(tx *storage.Connection) error {
			validToken, terr := models.GetValidChildToken(tx, token)
			if terr != nil {
				if errors.Is(terr, models.RefreshTokenNotFoundError{}) {
					// revoked token has no descendants
					return nil
				}
				return terr
			}
			// check if token is the last previous revoked token
			if validToken.Parent == storage.NullString(token.Token) {
				refreshTokenReuseWindow := token.UpdatedAt.Add(time.Second * time.Duration(config.Security.RefreshTokenReuseInterval))
				if time.Now().Before(refreshTokenReuseWindow) {
					newToken = validToken
				}
			}
			return nil
		})
		if err != nil {
			return internalServerError("Error validating reuse interval").WithInternalError(err)
		}

		if newToken == nil {
			if config.Security.RefreshTokenRotationEnabled {
				// Revoke all tokens in token family
				err = a.db.Transaction(func(tx *storage.Connection) error {
					var terr error
					if terr = models.RevokeTokenFamily(tx, token); terr != nil {
						return terr
					}
					return nil
				})
				if err != nil {
					return internalServerError(err.Error())
				}
			}
			return oauthError("invalid_grant", "Invalid Refresh Token").WithInternalMessage("Possible abuse attempt: %v", r)
		}
	}

	var tokenString string
	var newTokenResponse *AccessTokenResponse

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.TokenRefreshedAction, "", nil); terr != nil {
			return terr
		}

		if newToken == nil {
			newToken, terr = models.GrantRefreshTokenSwap(r, tx, user, token)
			if terr != nil {
				return internalServerError(terr.Error())
			}
		}

		tokenString, terr = generateAccessToken(user, newToken.SessionId.UUID.String(), time.Second*time.Duration(config.JWT.Exp), config.JWT.Secret)
		if terr != nil {
			return internalServerError("error generating jwt token").WithInternalError(terr)
		}

		newTokenResponse = &AccessTokenResponse{
			Token:        tokenString,
			TokenType:    "bearer",
			ExpiresIn:    config.JWT.Exp,
			RefreshToken: newToken.Token,
			User:         user,
		}
		if terr = a.setCookieTokens(config, newTokenResponse, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}

		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("token", user.ID)
	return sendJSON(w, http.StatusOK, newTokenResponse)
}

// IdTokenGrant implements the id_token grant type flow
func (a *API) IdTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	config := a.config

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
		verifier, err = params.getVerifierFromClientIDandIssuer(ctx)
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
	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
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

				user, terr = a.signupNewUser(ctx, tx, signupParams)
				if terr != nil {
					return terr
				}
				if identity, terr = a.createNewIdentity(tx, user, params.Provider, claims); terr != nil {
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
				if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength); terr != nil {
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

		token, terr = a.issueRefreshToken(ctx, tx, user)
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

func generateAccessToken(user *models.User, sessionId string, expiresIn time.Duration, secret string) (string, error) {
	claims := &GoTrueClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   user.ID.String(),
			Audience:  user.Aud,
			ExpiresAt: time.Now().Add(expiresIn).Unix(),
		},
		Email:        user.GetEmail(),
		Phone:        user.GetPhone(),
		AppMetaData:  user.AppMetaData,
		UserMetaData: user.UserMetaData,
		Role:         user.Role,
		SessionId:    sessionId,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func (a *API) issueRefreshToken(ctx context.Context, conn *storage.Connection, user *models.User) (*AccessTokenResponse, error) {
	config := a.config

	now := time.Now()
	user.LastSignInAt = &now

	var tokenString string
	var refreshToken *models.RefreshToken

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		refreshToken, terr = models.GrantAuthenticatedUser(tx, user)
		if terr != nil {
			return internalServerError("Database error granting user").WithInternalError(terr)
		}

		tokenString, terr = generateAccessToken(user, refreshToken.SessionId.UUID.String(), time.Second*time.Duration(config.JWT.Exp), config.JWT.Secret)
		if terr != nil {
			return internalServerError("error generating jwt token").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &AccessTokenResponse{
		Token:        tokenString,
		TokenType:    "bearer",
		ExpiresIn:    config.JWT.Exp,
		RefreshToken: refreshToken.Token,
		User:         user,
	}, nil
}

// setCookieTokens sets the access_token & refresh_token in the cookies
func (a *API) setCookieTokens(config *conf.GlobalConfiguration, token *AccessTokenResponse, session bool, w http.ResponseWriter) error {
	// don't need to catch error here since we always set the cookie name
	_ = a.setCookieToken(config, "access-token", token.Token, session, w)
	_ = a.setCookieToken(config, "refresh-token", token.RefreshToken, session, w)
	return nil
}

func (a *API) setCookieToken(config *conf.GlobalConfiguration, name string, tokenString string, session bool, w http.ResponseWriter) error {
	if name == "" {
		return errors.New("Failed to set cookie, invalid name")
	}
	cookieName := config.Cookie.Key + "-" + name
	exp := time.Second * time.Duration(config.Cookie.Duration)
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Domain:   config.Cookie.Domain,
	}
	if !session {
		cookie.Expires = time.Now().Add(exp)
		cookie.MaxAge = config.Cookie.Duration
	}

	http.SetCookie(w, cookie)
	return nil
}

func (a *API) clearCookieTokens(config *conf.GlobalConfiguration, w http.ResponseWriter) {
	a.clearCookieToken(config, "access-token", w)
	a.clearCookieToken(config, "refresh-token", w)
}

func (a *API) clearCookieToken(config *conf.GlobalConfiguration, name string, w http.ResponseWriter) {
	cookieName := config.Cookie.Key
	if name != "" {
		cookieName += "-" + name
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour * 10),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Domain:   config.Cookie.Domain,
	})
}
