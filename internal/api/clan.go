package api

import (
	"net/http"

	"github.com/clanwyse/halo/internal/models"
	"github.com/clanwyse/halo/internal/storage"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
)

// UserUpdateParams parameters for updating a user
type ClanCreateParams struct {
	Name        *string    `json:"name"`
	DisplayName *string    `json:"display_name"`
	Slug        *string    `json:"slug"`
	Email       *string    `json:"email"`
	ClanTypeID  *uuid.UUID `json:"clan_type_id"`
}

// ClanGet returns a clan
func (a *API) ClanCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	claims := getClaims(ctx)
	if claims == nil {
		return internalServerError("Could not read claims")
	}

	aud := a.requestAud(ctx, r)
	if aud != claims.Audience {
		return forbiddenError(ErrorCodeUnexpectedAudience, "Token audience doesn't match request audience")
	}

	params := &ClanCreateParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	user := getUser(ctx)

	clan, err := models.NewClan(*params.Name, *params.DisplayName, *params.Email, *params.Slug, *params.ClanTypeID, *user)

	if err != nil {
		return err
	}

	if terr := db.Create(clan); terr != nil {
		return internalServerError("Error creating identity").WithInternalError(terr)
	}
	return sendJSON(w, http.StatusOK, clan)
}

// ClanGet returns a clan
func (a *API) ClanGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	claims := getClaims(ctx)
	if claims == nil {
		return internalServerError("Could not read claims")
	}

	clanID, err := uuid.FromString(chi.URLParam(r, "clan_id"))
	if err != nil {
		return notFoundError(ErrorCodeValidationFailed, "clan_id must be an UUID")
	}

	aud := a.requestAud(ctx, r)
	if aud != claims.Audience {
		return forbiddenError(ErrorCodeUnexpectedAudience, "Token audience doesn't match request audience")
	}

	profile, err := models.FindClanByID(db, &clanID)

	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(ErrorCodeProfileNotFound, "Profile not found")
		}
		return internalServerError("Database error loading user").WithInternalError(err)
	}
	return sendJSON(w, http.StatusOK, profile)
}

// ClanUpdate updates fields on a clan
func (a *API) ClanUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	params := &ProfileUpdateParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	user := getUser(ctx)
	profile := models.Profile{}

	err := db.Transaction(func(tx *storage.Connection) error {
		var terr error

		if params.FirstName != nil {
			if terr = profile.UpdateFirstName(tx, params.FirstName); terr != nil {
				return internalServerError("Error updating profile").WithInternalError(terr)
			}
		}

		if params.LastName != nil {
			if terr = profile.UpdateLastName(tx, params.LastName); terr != nil {
				return internalServerError("Error updating profile").WithInternalError(terr)
			}
		}

		if params.Username != nil {
			if terr = profile.UpdateUsername(tx, params.Username); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.BirthDate != nil {
			if terr = profile.UpdateDOB(tx, params.BirthDate); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}
		if params.Bio != nil {
			if terr = profile.UpdateBio(tx, params.Bio); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if terr = models.NewAuditLogEntry(r, tx, user, models.UserModifiedAction, "", nil); terr != nil {
			return internalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, profile)
}
