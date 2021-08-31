package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// GoTrueClaims is a struct thats used for JWT claims
type GoTrueClaims struct {
	jwt.StandardClaims
	Email        string                 `json:"email"`
	Phone        string                 `json:"phone"`
	AppMetaData  map[string]interface{} `json:"app_metadata"`
	UserMetaData map[string]interface{} `json:"user_metadata"`
	Role         string                 `json:"role"`
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

const useCookieHeader = "x-use-cookie"
const useSessionCookie = "session"

// Token is the endpoint for OAuth access token requests
func (a *API) Token(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "password":
		return a.ResourceOwnerPasswordGrant(ctx, w, r)
	case "refresh_token":
		return a.RefreshTokenGrant(ctx, w, r)
	default:
		return oauthError("unsupported_grant_type", "")
	}
}

// ResourceOwnerPasswordGrant implements the password grant type flow
func (a *API) ResourceOwnerPasswordGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	params := &PasswordGrantParams{}

	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read password grant params: %v", err)
	}

	cookie := r.Header.Get(useCookieHeader)

	aud := a.requestAud(ctx, r)
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	if params.Email != "" && params.Phone != "" {
		return unprocessableEntityError("Only an email address or phone number should be provided on login.")
	}
	var user *models.User
	var err error
	if params.Email != "" {
		user, err = models.FindUserByEmailAndAudience(a.db, instanceID, params.Email, aud)
	} else if params.Phone != "" {
		params.Phone = a.formatPhoneNumber(params.Phone)
		user, err = models.FindUserByPhoneAndAudience(a.db, instanceID, params.Phone, aud)
	} else {
		return oauthError("invalid_grant", "Invalid login credentials")
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return oauthError("invalid_grant", "Invalid login credentials")
		}
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	if params.Email != "" && !user.IsConfirmed() {
		return oauthError("invalid_grant", "Email not confirmed")
	} else if params.Phone != "" && !user.IsPhoneConfirmed() {
		return oauthError("invalid_grant", "Phone not confirmed")
	}

	if !user.Authenticate(params.Password) {
		return oauthError("invalid_grant", "Invalid email or password")
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
			return terr
		}
		if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if cookie != "" && config.Cookie.Duration > 0 {
			if terr = a.setCookieToken(config, token.Token, cookie == useSessionCookie, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("password", user.ID, instanceID)
	token.User = user
	return sendJSON(w, http.StatusOK, token)
}

// RefreshTokenGrant implements the refresh_token grant type flow
func (a *API) RefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	params := &RefreshTokenGrantParams{}

	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read refresh token grant params: %v", err)
	}

	cookie := r.Header.Get(useCookieHeader)

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

	if token.Revoked {
		a.clearCookieToken(ctx, w)
		return oauthError("invalid_grant", "Invalid Refresh Token").WithInternalMessage("Possible abuse attempt: %v", r)
	}

	var tokenString string
	var newToken *models.RefreshToken

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.TokenRefreshedAction, nil); terr != nil {
			return terr
		}

		newToken, terr = models.GrantRefreshTokenSwap(tx, user, token)
		if terr != nil {
			return internalServerError(terr.Error())
		}

		if config.JWT.UsingPrivateKey() {
			tokenString, terr = generateAccessToken(user, time.Second*time.Duration(config.JWT.Exp), config.JWT.PrivateKey)
		} else {
			tokenString, terr = generateAccessToken(user, time.Second*time.Duration(config.JWT.Exp), config.JWT.PublicKey)
		}
		if terr != nil {
			return internalServerError("error generating jwt token").WithInternalError(terr)
		}

		if cookie != "" && config.Cookie.Duration > 0 {
			if terr = a.setCookieToken(config, tokenString, cookie == useSessionCookie, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("token", user.ID, instanceID)
	return sendJSON(w, http.StatusOK, &AccessTokenResponse{
		Token:        tokenString,
		TokenType:    "bearer",
		ExpiresIn:    config.JWT.Exp,
		RefreshToken: newToken.Token,
		User:         user,
	})
}

func generateAccessToken(user *models.User, expiresIn time.Duration, key interface{}) (string, error) {
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
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func (a *API) issueRefreshToken(ctx context.Context, conn *storage.Connection, user *models.User) (*AccessTokenResponse, error) {
	config := a.getConfig(ctx)

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

		if config.JWT.UsingPrivateKey() {
			tokenString, terr = generateAccessToken(user, time.Second*time.Duration(config.JWT.Exp), config.JWT.PrivateKey)
		} else {
			tokenString, terr = generateAccessToken(user, time.Second*time.Duration(config.JWT.Exp), config.JWT.PublicKey)
		}

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
	}, nil
}

func (a *API) setCookieToken(config *conf.Configuration, tokenString string, session bool, w http.ResponseWriter) error {
	exp := time.Second * time.Duration(config.Cookie.Duration)
	cookie := &http.Cookie{
		Name:     config.Cookie.Key,
		Value:    tokenString,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	}
	if !session {
		cookie.Expires = time.Now().Add(exp)
		cookie.MaxAge = config.Cookie.Duration
	}

	http.SetCookie(w, cookie)
	return nil
}

func (a *API) clearCookieToken(ctx context.Context, w http.ResponseWriter) {
	config := getConfig(ctx)
	http.SetCookie(w, &http.Cookie{
		Name:     config.Cookie.Key,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour * 10),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
	})
}
