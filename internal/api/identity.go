package api

import (
	"context"
	"net/http"

	"github.com/fatih/structs"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) DeleteIdentity(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	claims := getClaims(ctx)
	if claims == nil {
		return apierrors.NewInternalServerError("Could not read claims")
	}

	identityID, err := uuid.FromString(chi.URLParam(r, "identity_id"))
	if err != nil {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeValidationFailed, "identity_id must be an UUID")
	}

	aud := a.requestAud(ctx, r)
	audienceFromClaims, _ := claims.GetAudience()
	if len(audienceFromClaims) == 0 || aud != audienceFromClaims[0] {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeUnexpectedAudience, "Token audience doesn't match request audience")
	}

	user := getUser(ctx)
	if len(user.Identities) <= 1 {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeSingleIdentityNotDeletable, "User must have at least 1 identity after unlinking")
	}
	var identityToBeDeleted *models.Identity
	for i := range user.Identities {
		identity := user.Identities[i]
		if identity.ID == identityID {
			identityToBeDeleted = &identity
			break
		}
	}
	if identityToBeDeleted == nil {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeIdentityNotFound, "Identity doesn't exist")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.IdentityUnlinkAction, "", map[string]interface{}{
			"identity_id": identityToBeDeleted.ID,
			"provider":    identityToBeDeleted.Provider,
			"provider_id": identityToBeDeleted.ProviderID,
		}); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}
		if terr := tx.Destroy(identityToBeDeleted); terr != nil {
			return apierrors.NewInternalServerError("Database error deleting identity").WithInternalError(terr)
		}

		switch identityToBeDeleted.Provider {
		case "phone":
			user.PhoneConfirmedAt = nil
			if terr := user.SetPhone(tx, ""); terr != nil {
				return apierrors.NewInternalServerError("Database error updating user phone").WithInternalError(terr)
			}
			if terr := tx.UpdateOnly(user, "phone_confirmed_at"); terr != nil {
				return apierrors.NewInternalServerError("Database error updating user phone").WithInternalError(terr)
			}
		default:
			if terr := user.UpdateUserEmailFromIdentities(tx); terr != nil {
				if models.IsUniqueConstraintViolatedError(terr) {
					return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailConflictIdentityNotDeletable, "Unable to unlink identity due to email conflict").WithInternalError(terr)
				}
				return apierrors.NewInternalServerError("Database error updating user email").WithInternalError(terr)
			}
		}
		if terr := user.UpdateAppMetaDataProviders(tx); terr != nil {
			return apierrors.NewInternalServerError("Database error updating user providers").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{})
}

func (a *API) LinkIdentity(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	rurl, err := a.GetExternalProviderRedirectURL(w, r, user)
	if err != nil {
		return err
	}
	skipHTTPRedirect := r.URL.Query().Get("skip_http_redirect") == "true"
	if skipHTTPRedirect {
		return sendJSON(w, http.StatusOK, map[string]interface{}{
			"url": rurl,
		})
	}
	http.Redirect(w, r, rurl, http.StatusFound)
	return nil
}

func (a *API) linkIdentityToUser(r *http.Request, ctx context.Context, tx *storage.Connection, userData *provider.UserProvidedData, providerType string) (*models.User, error) {
	targetUser := getTargetUser(ctx)
	identity, terr := models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType)
	if terr != nil {
		if !models.IsNotFoundError(terr) {
			return nil, apierrors.NewInternalServerError("Database error finding identity for linking").WithInternalError(terr)
		}
	}
	if identity != nil {
		if identity.UserID == targetUser.ID {
			return nil, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeIdentityAlreadyExists, "Identity is already linked")
		}
		return nil, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeIdentityAlreadyExists, "Identity is already linked to another user")
	}
	if _, terr := a.createNewIdentity(tx, targetUser, providerType, structs.Map(userData.Metadata)); terr != nil {
		return nil, terr
	}

	if targetUser.GetEmail() == "" {
		if terr := targetUser.UpdateUserEmailFromIdentities(tx); terr != nil {
			if models.IsUniqueConstraintViolatedError(terr) {
				return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeEmailExists, DuplicateEmailMsg)
			}
			return nil, terr
		}
		if !userData.Metadata.EmailVerified {
			if terr := a.sendConfirmation(r, tx, targetUser, models.ImplicitFlow); terr != nil {
				return nil, terr
			}
			return nil, storage.NewCommitWithError(apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailNotConfirmed, "Unverified email with %v. A confirmation email has been sent to your %v email", providerType, providerType))
		}
		if terr := targetUser.Confirm(tx); terr != nil {
			return nil, terr
		}

		if targetUser.IsAnonymous {
			targetUser.IsAnonymous = false
			if terr := tx.UpdateOnly(targetUser, "is_anonymous"); terr != nil {
				return nil, terr
			}
		}
	}

	if terr := targetUser.UpdateAppMetaDataProviders(tx); terr != nil {
		return nil, terr
	}
	return targetUser, nil
}
