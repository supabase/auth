package api

import (
	"net/http"

	"github.com/clanwyse/halo/internal/models"
	"github.com/clanwyse/halo/internal/storage"
	"github.com/lpar/calendar"
)

// UserUpdateParams parameters for updating a user
type ProfileUpdateParams struct {
	FirstName           *string        `json:"first_name"`
	LastName            *string        `json:"last_name"`
	Username            *string        `json:"username"`
	Bio                 *string        `json:"bio"`
	BirthDate           *calendar.Date `json:"birth_date"`
	Channel             string         `json:"channel"`
	CodeChallenge       string         `json:"code_challenge"`
	CodeChallengeMethod string         `json:"code_challenge_method"`
}

// ProfileGet returns a profile
func (a *API) ProfileGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := getClaims(ctx)
	db := a.db.WithContext(ctx)
	if claims == nil {
		return internalServerError("Could not read claims")
	}

	aud := a.requestAud(ctx, r)
	if aud != claims.Audience {
		return badRequestError(ErrorCodeValidationFailed, "Token audience doesn't match request audience")
	}

	user := getUser(ctx)
	profile, err := models.FindProfileByID(db, user.ID)

	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(ErrorCodeProfileNotFound, "Profile not found")
		}
		return internalServerError("Database error loading user").WithInternalError(err)
	}
	return sendJSON(w, http.StatusOK, profile)
}

// ProfileUpdate updates fields on a profile
func (a *API) ProfileUpdate(w http.ResponseWriter, r *http.Request) error {
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
