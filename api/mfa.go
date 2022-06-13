package api

import (
	"encoding/json"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"net/http"
	"time"
)

type EnrollFactorParams struct {
	FactorID string `json:"factor_id"`
	FactorSimpleName string `json:"factor_simple_name"`
	FactorType string `json:"factor_type"`
}

// BackupCodesResponse repreesnts a successful Backup code generation response
type BackupCodesResponse struct {
	BackupCodes []string
}

type EnableMFAResponse struct {
	Success bool
	Error string
}

type DisableMFAResponse struct {
	Success bool
	Error   string
}

type EnrollFactorResponse struct {
	Id string
	CreatedAt string
	UpdatedAt string
	Type string
	// TOTP field once we include package

}

const NUM_BACKUP_CODES = 8

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	// instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.EnableMFA(tx); terr != nil {
			return internalServerError("Error enabling MFA").WithInternalError(terr)
		}

		// TODO(Joel): Add relevant IP header, admin, etc logging here
		// if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateBackupCodesAction, nil); terr != nil {
		// 	return terr
		// }
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, &EnableMFAResponse {
		Success: true,
		Error: "",
	})

}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	// instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.DisableMFA(tx); terr != nil {
			return internalServerError("Error Disabling MFA").WithInternalError(terr)
		}

		// TODO(Joel): Add relevant IP header, admin, etc logging here
		// if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateBackupCodesAction, nil); terr != nil {
		// 	return terr
		// }
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, &DisableMFAResponse{
		Success: true,
		Error:   "",
	})

}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	const MAX_FACTOR_LENGTH = 256
	const MAX_FACTOR_NAME_LENGTH = 256
	ctx := r.Context()
	user := getUser(ctx)
	// instanceID := getInstanceID(ctx)
	// // TODO: Convert this into a formal error
	if !user.MFAEnabled {
		return MFANotEnabledError
	}


	params := &EnrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read EnrollFactor params: %v", err)
	}

	if params.FactorID == "" || len(params.FactorID) > MAX_FACTOR_LENGTH {
		return unprocessableEntityError("FactorID needs to have between 0 and 256 characters")
	}

	if len(params.FactorSimpleName) > MAX_FACTOR_NAME_LENGTH {
		return unprocessableEntityError("FactorName needs to have between 0 and 256 characters")
	}
	// TODO: convert to enum
	if (params.FactorType != "totp") && (params.FactorType != "webauthn") {
		return unprocessableEntityError("FactorType needs to be either 'totp' or 'webauthn'")
	}

	factor, terr := models.NewFactor(user, params.FactorSimpleName, params.FactorID)
	if terr != nil {
		return internalServerError("Database error creating factor").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(factor); terr != nil {
			return terr
		}

		// TODO(Joel): Add relevant IP header, admin, etc logging here, Add relevant action log
		// if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateBackupCodesAction, nil); terr != nil {
		// 	return terr
		// }
		return terr
	})
	// Formulate appropriate response to give here
	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{

	})
}


// func (a *API) ListFactors(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	instanceID := getInstanceID(ctx)
// 	aud := a.requestAud(ctx, r)

// 	pageParams, err := paginate(r)
// 	if err != nil {
// 		return badRequestError("Bad Pagination Parameters: %v", err)
// 	}
// 	sortParams, err := sort(r, map[string]bool{models.CreatedAt: true}, []models.SortField{models.SortField{Name: models.CreatedAt, Dir: models.Descending}})
// 	if err != nil {
// 		return badRequestError("Bad Sort Parameters: %v", err)
// 	}

// 	filter := r.URL.Query().Get("filter")

// 	// TODO: Joel Add the corresponding endpoint to filter users
// 	factors, err := models.FindFactorsByUser(a.db, instanceID, aud, pageParams, sortParams, filter)
// 	if err != nil {
// 		return internalServerError("Database error finding factors").WithInternalError(err)
// 	}
// 	addPaginationHeaders(w, r, pageParams)


// 	// Remove aud here
// 	return sendJSON(w, http.StatusOK, map[string]interface{}{
// 		"factors": factors,
// 		"aud":   aud,
// 	})
// }

func (a *API) GenerateBackupCodes(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	// TODO: Convert this into a formal error
	if !user.MFAEnabled {
		return  MFANotEnabledError
	}
	now := time.Now()
	backupCodeModels := []*models.BackupCode{}
	var terr error
	var backupCode string
	var backupCodes []string
	var backupCodeModel *models.BackupCode

	for i := 0; i < NUM_BACKUP_CODES; i++ {
		backupCode = crypto.SecureToken()
		backupCodeModel, terr = models.NewBackupCode(user, backupCode, &now)
		if terr != nil {
			return internalServerError("Error creating backup code").WithInternalError(terr)
		}
		backupCodes = append(backupCodes, backupCode)
		backupCodeModels = append(backupCodeModels, backupCodeModel)
	}
	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(backupCodeModels); terr != nil {
			return terr
		}

		// TODO(Joel): Add relevant IP header, admin, etc logging here
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateBackupCodesAction, nil); terr != nil {
			return terr
		}
		return terr
	})

	return sendJSON(w, http.StatusOK, &BackupCodesResponse{
		BackupCodes: backupCodes,
	})
}
