package api

import (
	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// LinkIdentityWithIDTokenParams represents parameters for linking a new identity using an ID token
type LinkIdentityWithIDTokenParams struct {
	IdToken     string `json:"id_token"`
	Provider    string `json:"provider"`
	AccessToken string `json:"access_token,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Issuer      string `json:"issuer,omitempty"`

	GoTrueMetaSecurity
}

// LinkIdentityWithIDToken links a new identity to an existing user using an OIDC ID token
func (a *API) LinkIdentityWithIDToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	params := &LinkIdentityWithIDTokenParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.IdToken == "" {
		return badRequestError(ErrorCodeValidationFailed, "id_token is required")
	}

	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return badRequestError(ErrorCodeValidationFailed, "provider or client_id and issuer are required")
	}

	// Get the authenticated user from context
	user := getUser(ctx)
	if user == nil {
		return unauthorizedError("Missing authenticated user")
	}

	// Validate and parse the ID token
	idTokenParams := &IdTokenGrantParams{
		IdToken:     params.IdToken,
		AccessToken: params.AccessToken,
		Nonce:      params.Nonce,
		Provider:   params.Provider,
		ClientID:   params.ClientID,
		Issuer:     params.Issuer,
	}

	oidcProvider, skipNonceCheck, providerType, acceptableClientIDs, err := idTokenParams.getProvider(ctx, config, r)
	if err != nil {
		return err
	}

	idToken, userData, err := provider.ParseIDToken(ctx, oidcProvider, nil, params.IdToken, provider.ParseIDTokenOptions{
		SkipAccessTokenCheck: params.AccessToken == "",
		AccessToken:         params.AccessToken,
	})
	if err != nil {
		return oauthError("invalid_request", "Bad ID token").WithInternalError(err)
	}

	correctAudience := false
	for _, clientID := range acceptableClientIDs {
		if clientID == "" {
			continue
		}

		for _, aud := range idToken.Audience {
			if aud == clientID {
				correctAudience = true
				break
			}
		}

		if correctAudience {
			break
		}
	}

	if !correctAudience {
		return oauthError("invalid_request", "Unacceptable audience in id_token")
	}

	if !skipNonceCheck && params.Nonce != "" {
		// Verify nonce if provided
		if params.Nonce != idToken.Nonce {
			return oauthError("invalid_request", "Invalid nonce")
		}
	}

	// Process the link within a transaction
	err = db.Transaction(func(tx *storage.Connection) error {
		// Check if identity already exists
		identity, err := models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType)
		if err != nil {
			if !models.IsNotFoundError(err) {
				return internalServerError("Database error finding identity").WithInternalError(err)
			}
		}
		if identity != nil {
			if identity.UserID == user.ID {
				return unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to this user")
			}
			return unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to another user")
		}

		// Create new identity
		identityData := structs.Map(userData.Metadata)
		newIdentity, err := models.NewIdentity(user, providerType, identityData)
		if err != nil {
			return err
		}

		if err := tx.Create(newIdentity); err != nil {
			return internalServerError("Error creating identity").WithInternalError(err)
		}

		// Update user metadata 
		if err := user.UpdateUserMetaData(tx, identityData); err != nil {
			return internalServerError("Error updating user metadata").WithInternalError(err)
		}

		// Update app metadata providers
		if err := user.UpdateAppMetaDataProviders(tx); err != nil {
			return internalServerError("Error updating user providers").WithInternalError(err)
		}

		// Create audit log entry
		if err := models.NewAuditLogEntry(r, tx, user, models.IdentityLinkAction, "", map[string]interface{}{
			"provider": providerType,
			"identity_id": newIdentity.ID,
		}); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
