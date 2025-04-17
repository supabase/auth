package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// authCodeParams holds the `id` we care about.
type authCodeParams struct {
	ID string `json:"id"`
}

// Validate satisfies the IDRequestParams interface.
func (p *authCodeParams) Validate(r *http.Request, a *API) error {
	if p.ID == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed,
			"`id` is required")
	}
	return nil
}

// SetID is called in retrieveIDRequestParams if the caller does a GET request
// and we parse an `id` from query params.
func (p *authCodeParams) SetID(id string) {
	p.ID = id
}

// AuthCode is an example endpoint that uses our new helper function
// to read the user `id` from GET or POST. Then it returns a simple auth code.
func (a *API) AuthCode(w http.ResponseWriter, r *http.Request) error {
	params := &authCodeParams{}

	// Use your custom helper here instead of the usual retrieveRequestParams
	if err := retrieveIDRequestParams(r, params, a); err != nil {
		return err
	}

	userID, err := uuid.FromString(params.ID)
	if err != nil {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeValidationFailed,
			"Invalid user ID",
		).WithInternalError(err)
	}

	var code string
	err = a.db.Transaction(func(tx *storage.Connection) error {
		user, terr := models.FindUserByID(tx, userID)
		if terr != nil {
			if models.IsNotFoundError(terr) {
				return apierrors.NewNotFoundError(apierrors,
					"User not found",
				)
			}
			return terr
		}

		// Example of generating a flow state + auth code
		if _, terr = generateFlowState(
			tx,
			"auth-code",
			models.OTP,
			"",
			"",
			&user.ID,
		); terr != nil {
			return terr
		}

		code, terr = issueAuthCode(tx, user, models.OTP)
		if terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]string{
		"auth_code": code,
	})
}
