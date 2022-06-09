package api

import (
	"github.com/netlify/gotrue/crypto"
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
	Error string
}

const NUM_BACKUP_CODES = 8

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, make(map[string]string))

}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, &DisableMFAResponse{
		Success: true,
		Error: "",
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
	backupCodes := []string{}
	for i := 0; i < NUM_BACKUP_CODES; i++ {
		backupCodes = append(backupCodes, crypto.SecureToken())
	}

	timeCreated := time.Now().Format(time.RFC3339)
	// TODO(Joel): Add relevant IP header, admin, etc logging here
	return sendJSON(w, http.StatusOK, &BackupCodesResponse{
		BackupCodes: backupCodes,
		TimeCreated: timeCreated,
	})
}
