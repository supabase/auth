package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// authCodeParams holds the `id` + optional PKCE fields.
type authCodeParams struct {
	ID                  string `json:"id"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CodeChallenge       string `json:"code_challenge"`
}

// Validate checks for required fields & valid PKCE parameters.
func (p *authCodeParams) Validate(r *http.Request, a *API) error {
	if p.ID == "" {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeValidationFailed,
			"`id` is required",
		)
	}
	// Reuse the same PKCE validation helper used by MagicLinkParams, if available.
	if err := validatePKCEParams(p.CodeChallengeMethod, p.CodeChallenge); err != nil {
		return err
	}
	return nil
}

// SetID is only needed if you want to allow GET-based requests with a query param `id`.
func (p *authCodeParams) SetID(id string) {
	p.ID = id
}

// AuthCode demonstrates how to issue an auth code (or OTP) for a user, optionally
// storing PKCE data in FlowState if a code challenge is provided.
func (a *API) adminIssueAuthCode(w http.ResponseWriter, r *http.Request) error {
	params := &authCodeParams{}

	// Use your custom helper instead of the usual retrieveRequestParams.
	// This parses both GET query string and JSON body for an `id`.
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
				return apierrors.NewNotFoundError(
					apierrors.ErrorCodeUserNotFound,
					"User not found",
				)
			}
			return terr
		}

		// Decide whether this is a PKCE flow (S256, etc.) or a regular flow
		flowType := getFlowFromChallenge(params.CodeChallenge)

		// If PKCE flow, persist the flow state
		if isPKCEFlow(flowType) {
			if _, terr = generateFlowState(
				tx,
				models.OTP.String(), // Flow name or ID, e.g. "otp"
				models.OTP,          // FlowType
				params.CodeChallengeMethod,
				params.CodeChallenge,
				&user.ID,
			); terr != nil {
				return terr
			}
		}

		// Then issue the auth/OTP code, e.g. store it in your DB, send an email, etc.
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
