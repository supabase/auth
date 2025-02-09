package api

import (

	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/security"
	"github.com/supabase/auth/internal/storage"
)

// LinkIdentityWithIDTokenParams are the parameters for linking an identity using an ID token
type LinkIdentityWithIDTokenParams struct {
	IdToken     string `json:"id_token"`
	Provider    string `json:"provider"`
	AccessToken string `json:"access_token,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Issuer      string `json:"issuer,omitempty"`

	security.GotrueRequest
}

// LinkIdentityWithIDToken links a new identity to an existing user using an OIDC ID token
// LinkIdentityWithIDToken links a new identity to an existing user using an OIDC ID token
func (a *API) LinkIdentityWithIDToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	user := getUser(ctx)
	if user == nil {
		return unprocessableEntityError(ErrorCodeUserNotFound, "Missing authenticated user")
	}

	params := &IdTokenGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.IdToken == "" {
		return badRequestError(ErrorCodeValidationFailed, "id_token is required")
	}

	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return badRequestError(ErrorCodeValidationFailed, "provider or client_id and issuer are required")
	}

	oidcProvider, skipNonceCheck, providerType, acceptableClientIDs, err := params.getProvider(ctx, config, r)
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
		if params.Nonce != idToken.Nonce {
			return oauthError("invalid_nonce", "Invalid nonce")
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		// Check if identity already exists
		identity, terr := models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType)
		if terr != nil {
			if !models.IsNotFoundError(terr) {
				return internalServerError("Database error finding identity").WithInternalError(terr)
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
		newIdentity, terr := models.NewIdentity(user, providerType, identityData)
		if terr != nil {
			return terr
		}

		if terr := tx.Create(newIdentity); terr != nil {
			return internalServerError("Error creating identity").WithInternalError(terr)
		}

		// Update user metadata 
		if terr := user.UpdateUserMetaData(tx, identityData); terr != nil {
			return internalServerError("Error updating user metadata").WithInternalError(terr)
		}

		// Update app metadata providers
		if terr := user.UpdateAppMetaDataProviders(tx); terr != nil {
			return internalServerError("Error updating user providers").WithInternalError(terr)
		}

		// Create audit log entry
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserModifiedAction, "", map[string]interface{}{
			"provider": providerType,
		}); terr != nil {
			return terr
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
