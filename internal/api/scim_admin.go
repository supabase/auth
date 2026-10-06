package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

type AdminSCIMTokenCreateParams struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

type AdminSCIMTokenCreateResponse struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
	*models.SCIMToken
}

type AdminSCIMTokenListResponse struct {
	Tokens []models.SCIMToken `json:"tokens"`
}

type AdminSCIMStatusResponse struct {
	Enabled bool               `json:"enabled"`
	BaseURL string             `json:"base_url"`
	Tokens  []models.SCIMToken `json:"tokens"`
}

func (a *API) adminSCIMGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return a.sendSCIMStatus(w, a.db.WithContext(ctx), getSSOProvider(ctx))
}

func (a *API) adminSCIMEnable(w http.ResponseWriter, r *http.Request) error {
	return a.toggleSCIM(w, r, true)
}

func (a *API) adminSCIMDisable(w http.ResponseWriter, r *http.Request) error {
	return a.toggleSCIM(w, r, false)
}

func (a *API) toggleSCIM(w http.ResponseWriter, r *http.Request, enabled bool) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	set := models.DisableSCIM
	if enabled {
		set = models.EnableSCIM
	}
	if err := set(db, provider.ID); err != nil {
		return apierrors.NewInternalServerError("Error toggling SCIM").WithInternalError(err)
	}

	return a.sendSCIMStatus(w, db, provider)
}

func (a *API) adminSCIMTokensCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	params := &AdminSCIMTokenCreateParams{}
	if body, err := utilities.GetBodyBytes(r); err != nil || len(body) > 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}

	token, plaintext, err := models.CreateSCIMToken(db, provider.ID, params.ExpiresAt)
	if err != nil {
		if errors.Is(err, models.ErrSCIMTokenExpiry) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
		}
		return apierrors.NewInternalServerError("Error creating SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, &AdminSCIMTokenCreateResponse{
		BaseURL:   scim.BaseURL(a.config),
		Token:     plaintext,
		SCIMToken: token,
	})
}

func (a *API) adminSCIMTokensList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	tokens, err := models.FindSCIMTokensBySSOProvider(a.db.WithContext(ctx), provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error listing SCIM tokens").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMTokenListResponse{Tokens: tokens})
}

func (a *API) adminSCIMTokensRevoke(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	token, err := models.RevokeSCIMToken(db, provider.ID, uuid.FromStringOrNil(chi.URLParam(r, "token_id")))
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}

func (a *API) sendSCIMStatus(w http.ResponseWriter, db *storage.Connection, provider *models.SSOProvider) error {
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(db, provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM tokens").WithInternalError(err)
	}
	enabled := false
	if provider.IsEnabled() {
		if enabled, err = models.IsSCIMEnabled(db, provider.ID); err != nil {
			return apierrors.NewInternalServerError("Error finding SCIM settings").WithInternalError(err)
		}
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: enabled,
		BaseURL: scim.BaseURL(a.config),
		Tokens:  tokens,
	})
}
