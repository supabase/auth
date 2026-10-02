package api

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
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
	return a.setSCIM(w, r, true)
}

func (a *API) adminSCIMDisable(w http.ResponseWriter, r *http.Request) error {
	return a.setSCIM(w, r, false)
}

func (a *API) setSCIM(w http.ResponseWriter, r *http.Request, enabled bool) error {
	set, action, verb := models.DisableSCIM, models.SCIMDisabledAction, "disabling"
	if enabled {
		set, action, verb = models.EnableSCIM, models.SCIMEnabledAction, "enabling"
	}
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		changed, err := set(tx, provider.ID)
		if err != nil || !changed {
			return err
		}
		return a.auditSCIM(tx, r, scimAuditEvent{
			actor:      getAdminUser(ctx),
			action:     action,
			providerID: provider.ID,
			traits:     map[string]any{},
		})
	}); err != nil {
		return apierrors.NewInternalServerError("Error %s SCIM", verb).WithInternalError(err)
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

	token, plaintext, err := models.CreateSCIMToken(db, provider, params.ExpiresAt)
	if err != nil {
		if errors.Is(err, models.SCIMTokenExpiryError{}) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
		}
		return apierrors.NewInternalServerError("Error creating SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, &AdminSCIMTokenCreateResponse{
		BaseURL:   scimBaseURL(a.config),
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

	token, err := revokeSCIMToken(db, provider.ID, chi.URLParam(r, "prefix"))
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}

func revokeSCIMToken(tx *storage.Connection, providerID uuid.UUID, prefix string) (*models.SCIMToken, error) {
	token, err := models.FindSCIMTokenByPrefix(tx, providerID, prefix)
	if err != nil {
		return nil, err
	}
	if token.IsRevoked() {
		return token, nil
	}
	if err := token.Revoke(tx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.FindSCIMTokenByPrefix(tx, providerID, prefix)
		}
		return nil, err
	}
	return token, nil
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
		BaseURL: scimBaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) deprovisionSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) error {
	if !a.config.SSO.SCIM.Enabled {
		return nil
	}
	enabled, err := models.IsSCIMEnabled(tx, provider.ID)
	if err != nil || !enabled {
		return err
	}
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(tx, provider.ID)
	if err != nil {
		return err
	}
	prefixes := make([]string, len(tokens))
	for i, token := range tokens {
		prefixes[i] = token.Prefix
	}
	return a.auditSCIM(tx, r, scimAuditEvent{
		actor:      getAdminUser(r.Context()),
		action:     models.SCIMDisabledAction,
		providerID: provider.ID,
		traits:     map[string]any{"token_prefixes": prefixes},
	})
}
