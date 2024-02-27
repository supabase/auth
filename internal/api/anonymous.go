package api

import (
	"net/http"

	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) SignupAnonymously(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	params, err := retrieveSignupParams(r)
	if err != nil {
		return err
	}
	params.Aud = aud
	params.Provider = "anonymous"

	// always call this outside of a database transaction as this method
	// can be computationally hard and block due to password hashing
	newUser, err := params.ToUserModel(false /* <- isSSOUser */)
	if err != nil {
		return err
	}

	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)

	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		newUser, terr = a.signupNewUser(ctx, tx, newUser)
		if terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(ctx, tx, newUser, models.Anonymous, grantParams)
		if terr != nil {
			return terr
		}
		if terr := a.setCookieTokens(config, token, false, w); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return internalServerError("Database error creating anonymous user").WithInternalError(err)
	}

	metering.RecordLogin("anonymous", newUser.ID)
	return sendJSON(w, http.StatusOK, token)
}
