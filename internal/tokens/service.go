package tokens

import (
	"context"
	"fmt"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/xeipuuv/gojsonschema"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const retryLoopDuration = 5.0

// AccessTokenClaims is a struct thats used for JWT claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Email                         string                 `json:"email"`
	Phone                         string                 `json:"phone"`
	AppMetaData                   map[string]interface{} `json:"app_metadata"`
	UserMetaData                  map[string]interface{} `json:"user_metadata"`
	Role                          string                 `json:"role"`
	AuthenticatorAssuranceLevel   string                 `json:"aal,omitempty"`
	AuthenticationMethodReference []models.AMREntry      `json:"amr,omitempty"`
	SessionId                     string                 `json:"session_id,omitempty"`
	IsAnonymous                   bool                   `json:"is_anonymous"`
	ClientID                      string                 `json:"client_id,omitempty"`
}

// AccessTokenResponse represents an OAuth2 success response
type AccessTokenResponse struct {
	Token                string       `json:"access_token"`
	TokenType            string       `json:"token_type"` // Bearer
	ExpiresIn            int          `json:"expires_in"`
	ExpiresAt            int64        `json:"expires_at"`
	RefreshToken         string       `json:"refresh_token"`
	User                 *models.User `json:"user"`
	ProviderAccessToken  string       `json:"provider_token,omitempty"`
	ProviderRefreshToken string       `json:"provider_refresh_token,omitempty"`
	WeakPassword         interface{}  `json:"weak_password,omitempty"`
}

// GenerateAccessTokenParams contains parameters for generating access tokens
type GenerateAccessTokenParams struct {
	User                 *models.User
	SessionID            *uuid.UUID
	AuthenticationMethod models.AuthenticationMethod
	ClientID             *uuid.UUID // OAuth2 server client ID if applicable
}

// RefreshTokenGrantParams contains parameters for refresh token grant
type RefreshTokenGrantParams struct {
	RefreshToken string
	ClientID     *uuid.UUID // OAuth2 server client ID if applicable
}

// AsRedirectURL encodes the AccessTokenResponse as a redirect URL that
// includes the access token response data in a URL fragment.
func (r *AccessTokenResponse) AsRedirectURL(redirectURL string, extraParams url.Values) string {
	extraParams.Set("access_token", r.Token)
	extraParams.Set("token_type", r.TokenType)
	extraParams.Set("expires_in", strconv.Itoa(r.ExpiresIn))
	extraParams.Set("expires_at", strconv.FormatInt(r.ExpiresAt, 10))
	extraParams.Set("refresh_token", r.RefreshToken)

	return redirectURL + "#" + extraParams.Encode()
}

// HookManager interface for access token hooks
type HookManager interface {
	InvokeHook(tx *storage.Connection, r *http.Request, input any, output any) error
}

// Service handles token operations
type Service struct {
	config      *conf.GlobalConfiguration
	hookManager HookManager
	now         func() time.Time
}

// NewService creates a new token service
func NewService(config *conf.GlobalConfiguration, hookManager HookManager) *Service {
	if hookManager == nil {
		panic("token service requires hookManager")
	}

	return &Service{
		config:      config,
		hookManager: hookManager,
		now:         time.Now, // Default to system time
	}
}

// SetTimeFunc allows overriding the time function (only for testing!!)
func (s *Service) SetTimeFunc(timeFunc func() time.Time) {
	if timeFunc != nil {
		s.now = timeFunc
	}
}

// RefreshTokenGrant implements the refresh_token grant type flow
func (s *Service) RefreshTokenGrant(ctx context.Context, db *storage.Connection, r *http.Request, responseHeaders http.Header, params RefreshTokenGrantParams) (*AccessTokenResponse, error) {
	db = db.WithContext(ctx)
	config := s.config

	if params.RefreshToken == "" {
		return nil, apierrors.NewOAuthError("invalid_request", "refresh_token required")
	}

	// A 5 second retry loop is used to make sure that refresh token
	// requests do not waste database connections waiting for each other.
	// Instead of waiting at the database level, they're waiting at the API
	// level instead and retry to refresh the locked row every 10-30
	// milliseconds.
	retryStart := s.now()
	retry := true

	for retry && time.Since(retryStart).Seconds() < retryLoopDuration {
		retry = false

		user, anyToken, session, err := models.FindUserWithRefreshToken(db, config.Security.DBEncryption, params.RefreshToken, false)
		if err != nil {
			if models.IsNotFoundError(err) {
				return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenNotFound, "Invalid Refresh Token: Refresh Token Not Found")
			}
			return nil, apierrors.NewInternalServerError(err.Error())
		}

		responseHeaders.Set("sb-auth-user-id", user.ID.String())

		if user.IsBanned() {
			return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeUserBanned, "Invalid Refresh Token: User Banned")
		}

		if session == nil {
			if token, ok := anyToken.(*models.RefreshToken); ok {
				// a refresh token won't have a session if it's created prior to the sessions table introduced
				if err := db.Destroy(token); err != nil {
					return nil, apierrors.NewInternalServerError("Error deleting refresh token with missing session").WithInternalError(err)
				}
			}
			return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeSessionNotFound, "Invalid Refresh Token: No Valid Session Found")
		}

		responseHeaders.Set("sb-auth-session-id", session.ID.String())

		// OAuth client validation will be done inside the transaction
		var sessionClientID *uuid.UUID

		sessionValidityConfig := models.SessionValidityConfig{
			Timebox:           config.Sessions.Timebox,
			InactivityTimeout: config.Sessions.InactivityTimeout,
			AllowLowAAL:       config.Sessions.AllowLowAAL,
		}

		var refreshTokenTime *time.Time
		if token, ok := anyToken.(*models.RefreshToken); ok {
			refreshTokenTime = &token.UpdatedAt
		}

		result := session.CheckValidity(sessionValidityConfig, retryStart, refreshTokenTime, user.HighestPossibleAAL())

		switch result {
		case models.SessionValid:
			// do nothing

		case models.SessionTimedOut:
			return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeSessionExpired, "Invalid Refresh Token: Session Expired (Inactivity)")

		case models.SessionLowAAL:
			return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeSessionExpired, "Invalid Refresh Token: Session Expired (Low AAL: User Needs MFA Verification)")

		default:
			return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeSessionExpired, "Invalid Refresh Token: Session Expired")
		}

		// Basic checks above passed, now we need to serialize access
		// to the session in a transaction so that there's no
		// concurrent modification. In the event that the refresh
		// token's row or session is locked, the transaction is closed
		// and the whole process will be retried a bit later so that
		// the connection pool does not get exhausted.

		var tokenString string
		var expiresAt int64
		var newTokenResponse *AccessTokenResponse

		err = db.Transaction(func(tx *storage.Connection) error {
			user, anyToken, session, terr := models.FindUserWithRefreshToken(tx, config.Security.DBEncryption, params.RefreshToken, true /* forUpdate */)
			if terr != nil {
				if models.IsNotFoundError(terr) {
					// because forUpdate was set, and the
					// previous check outside the
					// transaction found a refresh token
					// and session, but now we're getting a
					// IsNotFoundError, this means that the
					// refresh token row and session are
					// probably locked so we need to retry
					// in a few milliseconds.
					retry = true
					return terr
				}
				return apierrors.NewInternalServerError(terr.Error())
			}

			// Validate OAuth client consistency between session and current request
			if session.OAuthClientID != nil && *session.OAuthClientID != uuid.Nil {
				// Session has an OAuth client, current request must have matching client
				if params.ClientID == nil || *params.ClientID == uuid.Nil {
					return apierrors.NewOAuthError("invalid_client", "Client authentication required for OAuth session")
				}
				if *params.ClientID != *session.OAuthClientID {
					return apierrors.NewOAuthError("invalid_client", "Client does not match the session's OAuth client")
				}
				sessionClientID = session.OAuthClientID
			} else {
				// Session has no OAuth client, current request should not have one either
				if params.ClientID != nil && *params.ClientID != uuid.Nil {
					return apierrors.NewOAuthError("invalid_client", "Client authentication not allowed for non-OAuth session")
				}
				sessionClientID = nil
			}

			if config.Sessions.SinglePerUser {
				sessions, terr := models.FindAllSessionsForUser(tx, user.ID, true /* forUpdate */)
				if models.IsNotFoundError(terr) {
					// because forUpdate was set, and the
					// previous check outside the
					// transaction found a user and
					// session, but now we're getting a
					// IsNotFoundError, this means that the
					// user is locked and we need to retry
					// in a few milliseconds
					retry = true
					return terr
				} else if terr != nil {
					return apierrors.NewInternalServerError(terr.Error())
				}

				sessionTag := session.DetermineTag(config.Sessions.Tags)

				// go through all sessions of the user and
				// check if the current session is the user's
				// most recently refreshed valid session
				for _, s := range sessions {
					if s.ID == session.ID {
						// current session, skip it
						continue
					}

					if s.CheckValidity(sessionValidityConfig, retryStart, nil, user.HighestPossibleAAL()) != models.SessionValid {
						// session is not valid so it
						// can't be regarded as active
						// on the user
						continue
					}

					if s.DetermineTag(config.Sessions.Tags) != sessionTag {
						// if tags are specified,
						// ignore sessions with a
						// mismatching tag
						continue
					}

					// since token is not the refresh token
					// of s, we can't use it's UpdatedAt
					// time to compare!
					if s.LastRefreshedAt(nil).After(session.LastRefreshedAt(refreshTokenTime)) {
						// session is not the most
						// recently active one
						return apierrors.NewBadRequestError(apierrors.ErrorCodeSessionExpired, "Invalid Refresh Token: Session Expired (Revoked by Newer Login)")
					}
				}

				// this session is the user's active session
			}

			// refresh token row and session are locked at this
			// point, cannot be concurrently refreshed

			var issuedToken string

			if token, ok := anyToken.(*models.RefreshToken); ok {
				if token.Revoked {
					activeRefreshToken, terr := session.FindCurrentlyActiveRefreshToken(tx)
					if terr != nil && !models.IsNotFoundError(terr) {
						return apierrors.NewInternalServerError(terr.Error())
					}

					if activeRefreshToken != nil && activeRefreshToken.Parent.String() == token.Token {
						// Token was revoked, but it's the
						// parent of the currently active one.
						// This indicates that the client was
						// not able to store the result when it
						// refreshed token. This case is
						// allowed, provided we return back the
						// active refresh token instead of
						// creating a new one.
						issuedToken = activeRefreshToken.Token
					} else {
						// For a revoked refresh token to be reused, it
						// has to fall within the reuse interval.
						reuseUntil := token.UpdatedAt.Add(
							time.Second * time.Duration(config.Security.RefreshTokenReuseInterval))

						if s.now().After(reuseUntil) {
							// not OK to reuse this token
							if config.Security.RefreshTokenRotationEnabled {
								// Revoke all tokens in token family
								if err := models.RevokeTokenFamily(tx, token); err != nil {
									return apierrors.NewInternalServerError(err.Error())
								}
							}

							return storage.NewCommitWithError(apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used").WithInternalMessage("Possible abuse attempt: %v", token.ID))
						}
					}
				}

				if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.TokenRefreshedAction, "", nil); terr != nil {
					return terr
				}

				if issuedToken == "" {
					newToken, terr := models.GrantRefreshTokenSwap(config.AuditLog, r, tx, user, token)
					if terr != nil {
						return terr
					}

					issuedToken = newToken.Token
				}

				responseHeaders.Set("sb-auth-refresh-token-prefix", issuedToken[0:5])
			} else if token, ok := anyToken.(*crypto.RefreshToken); ok {
				signingKey, _, kerr := session.GetRefreshTokenHmacKey(config.Security.DBEncryption)
				if kerr != nil {
					return apierrors.NewInternalServerError("failed to load session from database").WithInternalError(terr)
				}

				counterDifference := *session.RefreshTokenCounter - token.Counter

				if counterDifference < 0 {
					// refresh token was not issued by this server
					return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid Refresh Token: Not Issued By This Server").WithInternalMessage("Refresh token for session %s has a counter that's ahead %d of the database state", session.ID.String(), -counterDifference)
				} else if counterDifference == 0 {
					// normal refresh token use
					counter := *session.RefreshTokenCounter + 1
					session.RefreshTokenCounter = &counter

					issuedToken = (&crypto.RefreshToken{
						Version:   0,
						SessionID: session.ID,
						Counter:   *session.RefreshTokenCounter,
					}).Encode(signingKey)

					responseHeaders.Set("sb-auth-refresh-token-reuse", "false")
				} else if counterDifference > 0 {
					// refresh token is being reused

					// This is caused when the client has
					// failed to receive or save the
					// response from the last refresh token
					// requests. This occurs more
					// frequently than you can imagine, so
					// it's an allowed reuse.
					likelyNotSavedByClient := counterDifference == 1

					// Concurrent refreshes occur when the
					// client sends off multiple refresh
					// token requests at once or close by.
					// Often this happens when your browser
					// remembers multiple tabs of the app,
					// which were paused by it or by the OS
					// (such as you quitting the browser)
					// and then opening it back up. If the
					// app uses SSR it is likely that the N
					// open tabs will immediately send a
					// request to the app's hosting server,
					// which will attempt to concurrently
					// refresh the session at once using
					// refresh token.
					likelyConcurrentRefreshes := retryStart.Sub(session.LastRefreshedAt(nil)).Abs() < time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second

					var causes []string
					if likelyConcurrentRefreshes {
						causes = append(causes, "concurrent-refresh")
					}

					if likelyNotSavedByClient {
						causes = append(causes, "fail-to-save")
					}

					if config.Security.RefreshTokenAllowReuse {
						causes = append(causes, "always-allow")
					}

					headerValue := strings.Join(causes, ",")
					if headerValue != "" {
						responseHeaders.Set("sb-auth-refresh-token-reuse-cause", headerValue)
					}

					reuseAllowed := likelyNotSavedByClient || likelyConcurrentRefreshes || config.Security.RefreshTokenAllowReuse

					if reuseAllowed {
						// When reuse is allowed, we do
						// not increment the counter.
						// This allows all of the
						// concurrent clients to
						// synchronize their state
						// within the refresh token
						// reuse interval to the
						// currently active refresh
						// token.

						issuedToken = (&crypto.RefreshToken{
							Version:   0,
							SessionID: session.ID,
							Counter:   *session.RefreshTokenCounter,
						}).Encode(signingKey)

					} else if config.Security.RefreshTokenRotationEnabled {
						// Reuse is not allowed, in
						// which case the whole session
						// must go preventing any
						// client with any refresh and
						// access token for this
						// session from being used.

						if terr := models.LogoutSession(tx, session.ID); terr != nil {
							return apierrors.NewInternalServerError("destroying session after detected refresh token reuse failed").WithInternalError(terr)
						}

						responseHeaders.Set("sb-auth-refresh-token-rotated", "true")

						return storage.NewCommitWithError(apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used").WithInternalMessage("Refresh token behind current counter by %v, session %v is terminated due to refresh token reuse", counterDifference, session.ID.String()))
					} else {
						// Reuse is not allowed, but no
						// refresh token rotation
						// enabled. So only fail this
						// request.

						return storage.NewCommitWithError(apierrors.NewBadRequestError(apierrors.ErrorCodeRefreshTokenAlreadyUsed, "Invalid Refresh Token: Already Used").WithInternalMessage("Refresh token behind current counter by %v, session %v is not terminated but error is returned", counterDifference, session.ID.String()))
					}
				}

				if terr := session.UpdateOnlyRefreshToken(tx); terr != nil {
					return apierrors.NewInternalServerError("failed saving session").WithInternalError(terr)
				}

				responseHeaders.Set("sb-auth-refresh-token-counter", strconv.FormatInt(*session.RefreshTokenCounter, 10))

				if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.TokenRefreshedAction, "", nil); terr != nil {
					return terr
				}
			}

			tokenString, expiresAt, terr = s.GenerateAccessToken(r, tx, GenerateAccessTokenParams{
				User:                 user,
				SessionID:            &session.ID,
				AuthenticationMethod: models.TokenRefresh,
				ClientID:             sessionClientID,
			})
			if terr != nil {
				httpErr, ok := terr.(*apierrors.HTTPError)
				if ok {
					return httpErr
				}
				return apierrors.NewInternalServerError("error generating jwt token").WithInternalError(terr)
			}

			refreshedAt := s.now()
			session.RefreshedAt = &refreshedAt

			userAgent := r.Header.Get("User-Agent")
			if userAgent != "" {
				session.UserAgent = &userAgent
			} else {
				session.UserAgent = nil
			}

			ipAddress := utilities.GetIPAddress(r)
			if ipAddress != "" {
				session.IP = &ipAddress
			} else {
				session.IP = nil
			}

			if terr := session.UpdateOnlyRefreshInfo(tx); terr != nil {
				return apierrors.NewInternalServerError("failed to update session information").WithInternalError(terr)
			}

			newTokenResponse = &AccessTokenResponse{
				Token:        tokenString,
				TokenType:    "bearer",
				ExpiresIn:    config.JWT.Exp,
				ExpiresAt:    expiresAt,
				RefreshToken: issuedToken,
				User:         user,
			}

			return nil
		})
		if err != nil {
			if retry && models.IsNotFoundError(err) {
				// refresh token and session row were likely locked, so
				// we need to wait a moment before retrying the whole
				// process anew
				time.Sleep(time.Duration(10+mathRand.Intn(20)) * time.Millisecond) // #nosec
				continue
			} else {
				return nil, err
			}
		}
		metering.RecordLogin(metering.LoginTypeToken, user.ID, nil)
		return newTokenResponse, nil
	}

	return nil, apierrors.NewConflictError("Too many concurrent token refresh requests on the same session or refresh token")
}

// GenerateAccessToken generates an access token using shared logic
func (s *Service) GenerateAccessToken(r *http.Request, tx *storage.Connection, params GenerateAccessTokenParams) (string, int64, error) {
	config := s.config
	if params.SessionID == nil {
		return "", 0, apierrors.NewInternalServerError("Session is required to issue access token")
	}
	sid := params.SessionID.String()
	session, terr := models.FindSessionByID(tx, *params.SessionID, false)
	if terr != nil {
		return "", 0, terr
	}
	aal, amr, terr := session.CalculateAALAndAMR(params.User)
	if terr != nil {
		return "", 0, terr
	}

	issuedAt := s.now().UTC()
	expiresAt := issuedAt.Add(time.Second * time.Duration(config.JWT.Exp))
	var clientID string
	if params.ClientID != nil && *params.ClientID != uuid.Nil {
		clientID = params.ClientID.String()
	}

	claims := &v0hooks.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   params.User.ID.String(),
			Audience:  jwt.ClaimStrings{params.User.Aud},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    config.JWT.Issuer,
		},
		Email:                         params.User.GetEmail(),
		Phone:                         params.User.GetPhone(),
		AppMetaData:                   params.User.AppMetaData,
		UserMetaData:                  params.User.UserMetaData,
		Role:                          params.User.Role,
		SessionId:                     sid,
		AuthenticatorAssuranceLevel:   aal.String(),
		AuthenticationMethodReference: amr,
		IsAnonymous:                   params.User.IsAnonymous,
		ClientID:                      clientID,
	}

	var gotrueClaims jwt.Claims = claims
	if config.Hook.CustomAccessToken.Enabled {
		input := &v0hooks.CustomAccessTokenInput{
			UserID:               params.User.ID,
			Claims:               claims,
			AuthenticationMethod: params.AuthenticationMethod.String(),
		}

		output := &v0hooks.CustomAccessTokenOutput{}

		err := s.hookManager.InvokeHook(tx, r, input, output)
		if err != nil {
			return "", 0, err
		}
		if err := validateTokenClaims(output.Claims); err != nil {
			return "", 0, err
		}
		gotrueClaims = jwt.MapClaims(output.Claims)
	}

	signed, err := SignJWT(&config.JWT, gotrueClaims)
	if err != nil {
		return "", 0, err
	}
	return signed, expiresAt.Unix(), nil
}

// IssueRefreshToken creates a new refresh token and access token
func (s *Service) IssueRefreshToken(r *http.Request, responseHeaders http.Header, conn *storage.Connection, user *models.User, authenticationMethod models.AuthenticationMethod, grantParams models.GrantParams) (*AccessTokenResponse, error) {
	config := s.config

	now := s.now()
	user.LastSignInAt = &now

	var tokenString string
	var expiresAt int64
	var refreshToken string
	var sessionID uuid.UUID
	var oAuthClientID *uuid.UUID

	responseHeaders.Set("sb-auth-user-id", user.ID.String())

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error

		if config.Security.RefreshTokenAlgorithmVersion == 2 {
			session, terr := models.NewSession(user.ID, grantParams.FactorID)
			if terr != nil {
				return apierrors.NewInternalServerError("Failed to create new session").WithInternalError(terr)
			}

			session.ApplyGrantParams(&grantParams)
			if terr := session.SetupRefreshTokenData(config.Security.DBEncryption); terr != nil {
				return apierrors.NewInternalServerError("Failed to setup refresh token data for session").WithInternalError(terr)
			}

			if terr := tx.Create(session); terr != nil {
				return apierrors.NewInternalServerError("Database error creating new session").WithInternalError(terr)
			}

			signingKey, _, terr := session.GetRefreshTokenHmacKey(config.Security.DBEncryption)
			if terr != nil {
				return apierrors.NewInternalServerError("Failed to get session's refresh token key").WithInternalError(terr)
			}

			sessionID = session.ID
			refreshToken = (&crypto.RefreshToken{
				SessionID: session.ID,
				Counter:   *session.RefreshTokenCounter,
			}).Encode(signingKey)

			responseHeaders.Set("sb-auth-session-id", sessionID.String())
			responseHeaders.Set("sb-auth-refresh-token-counter", strconv.FormatInt(*session.RefreshTokenCounter, 10))
		} else {
			rt, terr := models.GrantAuthenticatedUser(tx, user, grantParams)
			if terr != nil {
				return apierrors.NewInternalServerError("Database error granting user").WithInternalError(terr)
			}

			sessionID = *rt.SessionId
			refreshToken = rt.Token

			responseHeaders.Set("sb-auth-session-id", sessionID.String())
			responseHeaders.Set("sb-auth-refresh-token-prefix", refreshToken[0:5])
		}

		if grantParams.OAuthClientID != nil && *grantParams.OAuthClientID != uuid.Nil {
			oAuthClientID = grantParams.OAuthClientID
		}

		terr = models.AddClaimToSession(tx, sessionID, authenticationMethod)
		if terr != nil {
			return terr
		}

		tokenString, expiresAt, terr = s.GenerateAccessToken(r, tx, GenerateAccessTokenParams{
			User:                 user,
			SessionID:            &sessionID,
			AuthenticationMethod: authenticationMethod,
			ClientID:             oAuthClientID,
		})
		if terr != nil {
			// Account for Hook Error
			if httpErr, ok := terr.(*apierrors.HTTPError); ok {
				return httpErr
			}
			return apierrors.NewInternalServerError("error generating jwt token").WithInternalError(terr)
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
		ExpiresAt:    expiresAt,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

// SignJWT signs a JWT token with the configured signing key
func SignJWT(config *conf.JWTConfiguration, claims jwt.Claims) (string, error) {
	signingJwk, err := conf.GetSigningJwk(config)
	if err != nil {
		return "", err
	}
	signingMethod := conf.GetSigningAlg(signingJwk)
	token := jwt.NewWithClaims(signingMethod, claims)
	if token.Header == nil {
		token.Header = make(map[string]interface{})
	}

	if _, ok := token.Header["kid"]; !ok {
		if kid := signingJwk.KeyID(); kid != "" {
			token.Header["kid"] = kid
		}
	}
	// this serializes the aud claim to a string
	jwt.MarshalSingleStringAsArray = false
	signingKey, err := conf.GetSigningKey(signingJwk)
	if err != nil {
		return "", err
	}
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}

var schemaLoader = gojsonschema.NewStringLoader(MinimumViableTokenSchema)

func validateTokenClaims(outputClaims map[string]interface{}) error {
	documentLoader := gojsonschema.NewGoLoader(outputClaims)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}

	if !result.Valid() {
		var errorMessages string

		for _, desc := range result.Errors() {
			errorMessages += fmt.Sprintf("- %s\n", desc)
		}
		err = fmt.Errorf(
			"output claims do not conform to the expected schema: \n%s", errorMessages)
	}
	if err != nil {
		httpError := &apierrors.HTTPError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		return httpError
	}
	return nil
}

// #nosec
const MinimumViableTokenSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "aud": {
      "type": ["string", "array"]
    },
    "exp": {
      "type": "integer"
    },
    "jti": {
      "type": "string"
    },
    "iat": {
      "type": "integer"
    },
    "iss": {
      "type": "string"
    },
    "nbf": {
      "type": "integer"
    },
    "sub": {
      "type": "string"
    },
    "email": {
      "type": "string"
    },
    "phone": {
      "type": "string"
    },
    "app_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "user_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "role": {
      "type": "string"
    },
    "aal": {
      "type": "string"
    },
    "amr": {
      "type": "array",
      "items": {
        "type": "object"
      }
    },
    "session_id": {
      "type": "string"
    },
    "client_id": {
      "type": "string"
    }
  },
  "required": ["aud", "exp", "iat", "sub", "email", "phone", "role", "aal", "session_id", "is_anonymous"]
}`
