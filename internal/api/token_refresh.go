package api

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/tokens"
)

// RefreshTokenGrantParams are the parameters the RefreshTokenGrant method accepts
type RefreshTokenGrantParams struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenGrant implements the refresh_token grant type flow
func (a *API) RefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	params := &RefreshTokenGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	db := a.db.WithContext(ctx)
	tokenResponse, err := a.tokenService.RefreshTokenGrant(ctx, db, r, tokens.RefreshTokenGrantParams{
		RefreshToken: params.RefreshToken,
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, tokenResponse)
}
