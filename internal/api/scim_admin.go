package api

import (
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

const (
	scimDeprovisionedBanDuration = 100 * 365 * 24 * time.Hour
	scimTokenPrefixTrait         = "token_prefix"
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
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		changed, err := models.EnableSCIM(tx, provider.ID)
		if err != nil || !changed {
			return err
		}
		return a.auditSCIM(tx, r, scimAuditEvent{
			actor:      getAdminUser(ctx),
			action:     models.SCIMEnabledAction,
			providerID: provider.ID,
			traits:     map[string]any{},
		})
	}); err != nil {
		return apierrors.NewInternalServerError("Error enabling SCIM").WithInternalError(err)
	}

	return a.sendSCIMStatus(w, db, provider)
}

func (a *API) adminSCIMDisable(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		changed, err := models.DisableSCIM(tx, provider.ID)
		if err != nil || !changed {
			return err
		}
		return a.auditSCIM(tx, r, scimAuditEvent{
			actor:      getAdminUser(ctx),
			action:     models.SCIMDisabledAction,
			providerID: provider.ID,
			traits:     map[string]any{},
		})
	}); err != nil {
		return apierrors.NewInternalServerError("Error disabling SCIM").WithInternalError(err)
	}

	return a.sendSCIMStatus(w, db, provider)
}

func (a *API) adminSCIMTokensCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	params, err := a.scimTokenCreateParams(r)
	if err != nil {
		return err
	}

	var (
		token     *models.SCIMToken
		plaintext string
	)
	if err := db.Transaction(func(tx *storage.Connection) error {
		if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
			return err
		}
		var err error
		if token, plaintext, err = models.CreateSCIMToken(tx, provider, params.ExpiresAt); err != nil {
			return err
		}
		return a.auditSCIM(tx, r, scimTokenAudit(getAdminUser(ctx), models.SCIMTokenCreatedAction, token))
	}); err != nil {
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

	var token *models.SCIMToken
	if err := db.Transaction(func(tx *storage.Connection) error {
		var err error
		token, err = a.revokeSCIMToken(tx, r, provider.ID, chi.URLParam(r, "prefix"))
		return err
	}); err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}

func (a *API) scimTokenCreateParams(r *http.Request) (*AdminSCIMTokenCreateParams, error) {
	params := &AdminSCIMTokenCreateParams{}
	if body, err := utilities.GetBodyBytes(r); err != nil || len(body) > 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return nil, err
		}
	}
	if params.ExpiresAt != nil && !params.ExpiresAt.After(a.Now()) {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
	}
	return params, nil
}

func (a *API) revokeSCIMToken(tx *storage.Connection, r *http.Request, providerID uuid.UUID, prefix string) (*models.SCIMToken, error) {
	if err := models.LockSCIMTokens(tx, providerID); err != nil {
		return nil, err
	}
	token, err := models.FindSCIMTokenByPrefix(tx, providerID, prefix)
	if err != nil {
		return nil, err
	}
	if token.IsRevoked() {
		return token, nil
	}
	if err := token.Revoke(tx); err != nil {
		return nil, err
	}
	return token, a.auditSCIM(tx, r, scimTokenAudit(getAdminUser(r.Context()), models.SCIMTokenRevokedAction, token))
}

func (a *API) sendSCIMStatus(w http.ResponseWriter, db *storage.Connection, provider *models.SSOProvider) error {
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(db, provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM tokens").WithInternalError(err)
	}
	enabled, err := a.isSCIMEnabled(db, provider)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM settings").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: enabled,
		BaseURL: scimBaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) isSCIMEnabled(db *storage.Connection, provider *models.SSOProvider) (bool, error) {
	if !a.config.SSO.SCIM.Enabled || !provider.IsEnabled() {
		return false, nil
	}
	return models.IsSCIMEnabled(db, provider.ID)
}

func (a *API) deprovisionSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) error {
	enabled, err := models.IsSCIMEnabled(tx, provider.ID)
	if err != nil {
		return err
	}
	actor := getAdminUser(r.Context())
	prefixes, err := a.revokeActiveSCIMTokens(tx, r, actor, provider.ID)
	if err != nil {
		return err
	}
	if enabled && a.config.SSO.SCIM.Enabled {
		if err := a.auditSCIMDisabled(tx, r, provider.ID, prefixes); err != nil {
			return err
		}
	}
	banned, err := models.BanDeprovisionedSCIMUsers(tx, provider.ID, a.Now().Add(scimDeprovisionedBanDuration))
	if err != nil || banned == 0 {
		return err
	}
	return a.auditSCIM(tx, r, scimAuditEvent{
		actor:      actor,
		action:     models.SCIMUsersBannedAction,
		providerID: provider.ID,
		traits:     map[string]any{"banned_user_count": banned},
	})
}

func (a *API) revokeActiveSCIMTokens(tx *storage.Connection, r *http.Request, actor *models.User, providerID uuid.UUID) ([]string, error) {
	if err := models.LockSCIMTokens(tx, providerID); err != nil {
		return nil, err
	}
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(tx, providerID)
	if err != nil {
		return nil, err
	}
	prefixes := make([]string, len(tokens))
	events := make([]scimAuditEvent, len(tokens))
	for i := range tokens {
		prefixes[i] = tokens[i].Prefix
		if err := tokens[i].Revoke(tx); err != nil {
			return nil, err
		}
		events[i] = scimTokenAudit(actor, models.SCIMTokenRevokedAction, &tokens[i])
	}
	return prefixes, a.auditSCIMEvents(tx, r, events)
}

func scimTokenAudit(actor *models.User, action models.AuditAction, token *models.SCIMToken) scimAuditEvent {
	return scimAuditEvent{
		actor:      actor,
		action:     action,
		providerID: token.SSOProviderID,
		traits:     map[string]any{scimTokenPrefixTrait: token.Prefix},
	}
}

func (a *API) auditSCIMDisabled(tx *storage.Connection, r *http.Request, providerID uuid.UUID, prefixes []string) error {
	return a.auditSCIM(tx, r, scimAuditEvent{
		actor:      getAdminUser(r.Context()),
		action:     models.SCIMDisabledAction,
		providerID: providerID,
		traits:     map[string]any{"token_prefixes": prefixes},
	})
}
