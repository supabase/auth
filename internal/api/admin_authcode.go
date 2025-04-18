package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type authCodeParams struct {
	ID                  string `json:"id"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CodeChallenge       string `json:"code_challenge"`
}

func (p *authCodeParams) Validate(r *http.Request, a *API) error {
	if p.ID == "" {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeValidationFailed,
			"`id` is required",
		)
	}
	if err := validatePKCEParams(p.CodeChallengeMethod, p.CodeChallenge); err != nil {
		return err
	}
	return nil
}

func (p *authCodeParams) SetID(id string) {
	p.ID = id
}

func (a *API) adminIssueAuthCode(w http.ResponseWriter, r *http.Request) error {
	params := &authCodeParams{}

	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		if strings.Contains(err.Error(), "EOF") {
			return apierrors.NewBadRequestError(
				apierrors.ErrorCodeValidationFailed,
				"Request body must not be empty",
			)
		}
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
				return apierrors.NewNotFoundError(
					apierrors.ErrorCodeUserNotFound,
					"User not found",
				)
			}
			return terr
		}

		if terr := models.NewAuditLogEntry(
			r,
			tx,
			user,
			models.IssueAuthCodeAction,
			"",
			map[string]interface{}{
				"user_id": user.ID,
			},
		); terr != nil {
			return terr
		}

		if _, terr = generateFlowState(
			tx,
			models.OTP.String(),
			models.OTP,
			params.CodeChallengeMethod,
			params.CodeChallenge,
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
