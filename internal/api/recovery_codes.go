package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// RecoveryCodesGenerateParams are the parameters for generating recovery codes.
type RecoveryCodesGenerateParams struct {
	FriendlyName string `json:"friendly_name"`
}

// RecoveryCodesResponse is the response shared by the recovery-code endpoints.
// The codes are only returned once, on generation.
type RecoveryCodesResponse struct {
	ID           uuid.UUID `json:"id"`
	Type         string    `json:"type"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	Total        int       `json:"total"`
	Remaining    *int      `json:"remaining,omitempty"`
	Codes        []string  `json:"codes,omitempty"`
}

// generateRecoveryCodes generates the configured number of recovery codes,
// returning the canonical plaintexts and their hashes.
func generateRecoveryCodes(config *conf.GlobalConfiguration) ([]string, []string, error) {
	count := config.MFA.RecoveryCodes.Count
	codes := make([]string, 0, count)
	hashes := make([]string, 0, count)

	for range count {
		code := crypto.GenerateRecoveryCode(config.MFA.RecoveryCodes.CodeLength)
		hash, err := crypto.GenerateRecoveryCodeHash(code)
		if err != nil {
			return nil, nil, apierrors.NewInternalServerError("Error generating recovery codes").WithInternalError(err)
		}

		codes = append(codes, code)
		hashes = append(hashes, hash)
	}

	return codes, hashes, nil
}

// generateAndStoreRecoveryCodeSet generates the configured number of codes,
// persists the set and hashed code rows for factor inside tx, and returns the plaintexts.
func generateAndStoreRecoveryCodeSet(tx *storage.Connection, config *conf.GlobalConfiguration, factor *models.Factor) ([]string, error) {
	codes, hashes, err := generateRecoveryCodes(config)
	if err != nil {
		return nil, err
	}

	if _, err := models.CreateRecoveryCodeSet(tx, factor, hashes); err != nil {
		return nil, apierrors.NewInternalServerError("Database error creating recovery codes").WithInternalError(err)
	}

	return codes, nil
}

// RecoveryCodesStatus returns the recovery-code enrollment status and counts,
// never code values or lockout state.
func (a *API) RecoveryCodesStatus(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	db := a.db.WithContext(ctx)

	if user == nil {
		return apierrors.NewInternalServerError("An authenticated user is required to view recovery codes")
	}

	set, err := models.FindRecoveryCodeSetByUser(db, user.ID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeMFAFactorNotFound, "Recovery codes are not enrolled for this user")
		}
		return apierrors.NewInternalServerError("Database error finding recovery code set").WithInternalError(err)
	}

	total, remaining, err := models.CountRecoveryCodes(db, set.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Database error counting recovery codes").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		ID:        set.MFAFactorID, // we return the factor ID, not the set ID, to match the other factor endpoints.
		Type:      models.RecoveryCode,
		Total:     total,
		Remaining: &remaining,
	})
}

// RecoveryCodesGenerate creates the user's recovery-code factor and one-time
// set of codes, returning the plaintexts exactly once.
func (a *API) RecoveryCodesGenerate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	if session == nil || user == nil {
		return apierrors.NewInternalServerError("A valid session and a registered user are required to generate recovery codes")
	}

	if !config.MFA.RecoveryCodes.EnrollEnabled {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFARecoveryCodesEnrollDisabled, "MFA enroll is disabled for recovery codes")
	}

	// The body is optional; only parse it when one was sent.
	params := &RecoveryCodesGenerateParams{}
	if body, _ := utilities.GetBodyBytes(r); len(body) != 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}

	if !session.IsAAL2() {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeInsufficientAAL, "AAL2 required to generate recovery codes")
	}

	factor := models.NewRecoveryCodeFactor(user, params.FriendlyName)

	if err := validateFactors(db, user, factor.FriendlyName, config, session); err != nil {
		return err
	}

	// Recovery codes can never be the user's only second factor.
	hasOtherVerifiedFactor := false
	for _, f := range user.Factors {
		if f.IsVerified() && !f.IsRecoveryCodeFactor() {
			hasOtherVerifiedFactor = true
			break
		}
	}
	if !hasOtherVerifiedFactor {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFARecoveryCodesSoleFactor, "At least one other verified factor is required to generate recovery codes")
	}

	if _, err := models.FindRecoveryCodeSetByUser(db, user.ID); err == nil {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAVerifiedFactorExists, "Recovery codes are already enrolled for this user, use regenerate to rotate them")
	} else if !models.IsNotFoundError(err) {
		return apierrors.NewInternalServerError("Database error finding recovery code set").WithInternalError(err)
	}

	var codes []string
	err := db.Transaction(func(tx *storage.Connection) error {
		// The unique user_id on mfa_recovery_code_sets ensures that only one
		// recovery-code factor can be created per user.
		if terr := tx.Create(factor); terr != nil {
			return terr
		}

		var terr error
		if codes, terr = generateAndStoreRecoveryCodeSet(tx, config, factor); terr != nil {
			return terr
		}

		return models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.RecoveryCodesGeneratedAction, utilities.GetIPAddress(r), map[string]any{
			"factor_id": factor.ID,
			"count":     len(codes),
		})
	})
	if err != nil {
		return err
	}

	if config.Mailer.Notifications.MFAFactorEnrolledEnabled && user.GetEmail() != "" {
		if err := a.sendMFAFactorEnrolledNotification(r, db, user, factor.FactorType); err != nil {
			logrus.WithError(err).Warn("Unable to send MFA factor enrolled notification email")
		}
	}

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		ID:           factor.ID,
		Type:         models.RecoveryCode,
		FriendlyName: factor.FriendlyName,
		Total:        len(codes),
		Codes:        codes,
	})
}
