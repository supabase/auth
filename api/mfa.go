package api

import (
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"net/http"
	"time"
)

// BackupCodesResponse repreesnts a successful Backup code generation response
type BackupCodesResponse struct {
	BackupCodes []string
	TimeCreated string
}

type EnableMFAResponse struct {
}

type DisableMFAResponse struct {
	Success bool
	Error   string
}

const NUM_BACKUP_CODES = 8

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
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
	return sendJSON(w, http.StatusOK, make(map[string]string))
}

func (a *API) GenerateBackupCodes(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	// if !user.MFAEnabled {
	// 	return "MFA not enabled"
	// }
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
		TimeCreated: now.String(),
	})
}
