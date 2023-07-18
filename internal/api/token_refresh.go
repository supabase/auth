package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

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

	user, token, session, err := models.FindUserWithRefreshToken(db, params.RefreshToken)
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

	if token.Revoked {
		a.clearCookieTokens(config, w)
		// For a revoked refresh token to be reused, it has to fall within the reuse interval.

		reuseUntil := token.UpdatedAt.Add(
			time.Second * time.Duration(config.Security.RefreshTokenReuseInterval))

		if time.Now().After(reuseUntil) {
			// not OK to reuse this token

			if config.Security.RefreshTokenRotationEnabled {
				// Revoke all tokens in token family
				err = db.Transaction(func(tx *storage.Connection) error {
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

			return oauthError("invalid_grant", "Invalid Refresh Token: Already Used").WithInternalMessage("Possible abuse attempt: %v", token.ID)
		}
	}

	var tokenString string
	var newTokenResponse *AccessTokenResponse

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
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

		tokenString, terr = generateAccessToken(tx, user, newToken.SessionId, &config.JWT)

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
