package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// SCIMProviderCreateRequest is the request body for creating a SCIM provider
type SCIMProviderCreateRequest struct {
	Name     string `json:"name"`
	Audience string `json:"audience,omitempty"`
}

// SCIMProviderCreateResponse includes the generated token (only shown once)
type SCIMProviderCreateResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Audience  string    `json:"audience,omitempty"`
	Token     string    `json:"token"`
	CreatedAt string    `json:"created_at"`
}

// SCIMProviderResponse is the standard response for provider details (without token)
type SCIMProviderResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Audience  string    `json:"audience,omitempty"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

// SCIMProviderListResponse is the response for listing providers
type SCIMProviderListResponse struct {
	Providers []SCIMProviderResponse `json:"providers"`
	Total     int                    `json:"total"`
}

// SCIMProviderRotateTokenResponse includes the new token (only shown once)
type SCIMProviderRotateTokenResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	UpdatedAt string    `json:"updated_at"`
}

// AdminSCIMProviderCreate creates a new SCIM provider
func (a *API) AdminSCIMProviderCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	var req SCIMProviderCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid request body")
	}

	if req.Name == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Provider name is required")
	}

	// Check if provider with this name already exists
	existing, _ := models.FindSCIMProviderByName(db, req.Name)
	if existing != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Provider with this name already exists")
	}

	// Generate a secure random token
	token, err := generateSCIMToken()
	if err != nil {
		return apierrors.NewInternalServerError("Failed to generate token")
	}

	// Create the provider
	provider, err := models.NewSCIMProvider(req.Name, token, req.Audience)
	if err != nil {
		return apierrors.NewInternalServerError("Failed to create provider")
	}

	// Save to database
	if err := db.Create(provider); err != nil {
		return apierrors.NewInternalServerError("Failed to save provider")
	}

	// Return response with token (only time it's shown)
	resp := SCIMProviderCreateResponse{
		ID:        provider.ID,
		Name:      provider.Name,
		Audience:  provider.Audience,
		Token:     token,
		CreatedAt: provider.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	w.WriteHeader(http.StatusCreated)
	return sendJSON(w, http.StatusCreated, resp)
}

// AdminSCIMProviderList lists all SCIM providers
func (a *API) AdminSCIMProviderList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	providers, err := models.FindAllSCIMProviders(db, 0, 0)
	if err != nil {
		return apierrors.NewInternalServerError("Failed to list providers")
	}

	total, err := models.CountSCIMProviders(db)
	if err != nil {
		return apierrors.NewInternalServerError("Failed to count providers")
	}

	responses := make([]SCIMProviderResponse, len(providers))
	for i, p := range providers {
		responses[i] = SCIMProviderResponse{
			ID:        p.ID,
			Name:      p.Name,
			Audience:  p.Audience,
			CreatedAt: p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			UpdatedAt: p.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
	}

	resp := SCIMProviderListResponse{
		Providers: responses,
		Total:     total,
	}

	return sendJSON(w, http.StatusOK, resp)
}

// AdminSCIMProviderGet gets a specific SCIM provider
func (a *API) AdminSCIMProviderGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	providerID, err := uuid.FromString(chi.URLParam(r, "provider_id"))
	if err != nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
	}

	provider, err := models.FindSCIMProviderByID(db, providerID)
	if err != nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
	}

	resp := SCIMProviderResponse{
		ID:        provider.ID,
		Name:      provider.Name,
		Audience:  provider.Audience,
		CreatedAt: provider.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: provider.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return sendJSON(w, http.StatusOK, resp)
}

// AdminSCIMProviderRotateToken rotates the token for a SCIM provider
func (a *API) AdminSCIMProviderRotateToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	providerID, err := uuid.FromString(chi.URLParam(r, "provider_id"))
	if err != nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
	}

	var provider *models.SCIMProvider
	err = db.Transaction(func(tx *storage.Connection) error {
		p, terr := models.FindSCIMProviderByID(tx, providerID)
		if terr != nil {
			return terr
		}
		provider = p

		// Generate new token
		newToken, terr := generateSCIMToken()
		if terr != nil {
			return terr
		}

		// Update the token
		if terr := provider.UpdateToken(tx, newToken); terr != nil {
			return terr
		}

		// Store token in response (we'll use it after transaction)
		provider.PasswordHash = newToken // Temporarily store plaintext for response
		return nil
	})

	if err != nil {
		if _, ok := err.(models.SCIMProviderNotFoundError); ok {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
		}
		return apierrors.NewInternalServerError("Failed to rotate token")
	}

	resp := SCIMProviderRotateTokenResponse{
		ID:        provider.ID,
		Name:      provider.Name,
		Token:     provider.PasswordHash, // This is the plaintext token we stored temporarily
		UpdatedAt: provider.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return sendJSON(w, http.StatusOK, resp)
}

// AdminSCIMProviderDelete soft-deletes a SCIM provider
func (a *API) AdminSCIMProviderDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	providerID, err := uuid.FromString(chi.URLParam(r, "provider_id"))
	if err != nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		provider, terr := models.FindSCIMProviderByID(tx, providerID)
		if terr != nil {
			return terr
		}

		return provider.SoftDelete(tx)
	})

	if err != nil {
		if _, ok := err.(models.SCIMProviderNotFoundError); ok {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSSOProviderNotFound, "SCIM provider not found")
		}
		return apierrors.NewInternalServerError("Failed to delete provider")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// generateSCIMToken generates a cryptographically secure random token
func generateSCIMToken() (string, error) {
	// Generate 32 bytes of random data
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Encode as base64 URL-safe string (no padding)
	token := base64.RawURLEncoding.EncodeToString(b)
	return token, nil
}
