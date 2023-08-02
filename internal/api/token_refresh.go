package api

import (
	"context"
	"encoding/json"
	mathRand "math/rand"
	"net/http"
	"time"

	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

const retryLoopDuration = 5.0

// RefreshTokenGrantParams are the parameters the RefreshTokenGrant method accepts
type RefreshTokenGrantParams struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenGrant implements the refresh_token grant type flow
func (a *API) RefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)
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

	// A 5 second retry loop is used to make sure that refresh token
	// requests do not waste database connections waiting for each other.
	// Instead of waiting at the database level, they're waiting at the API
	// level instead and retry to refresh the locked row every 10-30
	// milliseconds.
	retryStart := time.Now()
	retry := true

	for retry && time.Since(retryStart).Seconds() < retryLoopDuration {
		retry = false

		user, _, session, err := models.FindUserWithRefreshToken(db, params.RefreshToken, false)
		if err != nil {
			if models.IsNotFoundError(err) {
				return oauthError("invalid_grant", "Invalid Refresh Token: Refresh Token Not Found")
			}
			return internalServerError(err.Error())
		}

		if user.IsBanned() {
			return oauthError("invalid_grant", "Invalid Refresh Token: User Banned")
		}

		if session != nil {
			var notAfter time.Time

			if session.NotAfter != nil {
				notAfter = *session.NotAfter
			}

			if !notAfter.IsZero() && time.Now().UTC().After(notAfter) {
				return oauthError("invalid_grant", "Invalid Refresh Token: Session Expired")
			}
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
			user, token, _, terr := models.FindUserWithRefreshToken(tx, params.RefreshToken, true /* forUpdate */)
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
				return internalServerError(terr.Error())
			}

			// refresh token row and session are locked at this
			// point, cannot be concurrently refreshed

			if token.Revoked {
				a.clearCookieTokens(config, w)
				// For a revoked refresh token to be reused, it
				// has to fall within the reuse interval.

				reuseUntil := token.UpdatedAt.Add(
					time.Second * time.Duration(config.Security.RefreshTokenReuseInterval))

				if time.Now().After(reuseUntil) {
					// not OK to reuse this token

					if config.Security.RefreshTokenRotationEnabled {
						// Revoke all tokens in token family
						if err := models.RevokeTokenFamily(tx, token); err != nil {
							return internalServerError(err.Error())
						}
					}

					return oauthError("invalid_grant", "Invalid Refresh Token: Already Used").WithInternalMessage("Possible abuse attempt: %v", token.ID)
				}
			}

			if terr = models.NewAuditLogEntry(r, tx, user, models.TokenRefreshedAction, "", nil); terr != nil {
				return terr
			}

			// a new refresh token is generated and explicitly not reusing
			// a previous one as it could have already been revoked while
			// this handler was running
			newToken, terr := models.GrantRefreshTokenSwap(r, tx, user, token)
			if terr != nil {
				return terr
			}

			tokenString, expiresAt, terr = generateAccessToken(tx, user, newToken.SessionId, &config.JWT)

			if terr != nil {
				return internalServerError("error generating jwt token").WithInternalError(terr)
			}

			newTokenResponse = &AccessTokenResponse{
				Token:        tokenString,
				TokenType:    "bearer",
				ExpiresIn:    config.JWT.Exp,
				ExpiresAt:    expiresAt,
				RefreshToken: newToken.Token,
				User:         user,
			}
			if terr = a.setCookieTokens(config, newTokenResponse, false, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}

			return nil
		})
		if err == nil {
			// success
			metering.RecordLogin("token", user.ID)
			return sendJSON(w, http.StatusOK, newTokenResponse)
		}

		if err != nil {
			if retry && models.IsNotFoundError(err) {
				// refresh token and session row were likely locked, so
				// we need to wait a moment before retrying the whole
				// process anew
				time.Sleep(time.Duration(10+mathRand.Intn(20)) * time.Millisecond) // #nosec
				continue
			} else {
				return err
			}
		}
	}

	return conflictError("Too many concurrent token refresh requests on the same session or refresh token")
}
