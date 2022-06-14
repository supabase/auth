package api

import (
	"encoding/json"
	"github.com/pquerna/otp/totp"
	"bytes"
	"encoding/base64"
	"fmt"
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
}

type DisableMFAResponse struct {
	Success bool
}

type TOTPObject struct {
	QRCode string
	Secret string
	URI string
}

type EnrollFactorResponse struct {
	ID string
	CreatedAt string
	Type string
	TOTP TOTPObject
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
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, &EnableMFAResponse {
		Success: true,
	})

}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.DisableMFA(tx); terr != nil {
			return internalServerError("Error Disabling MFA").WithInternalError(terr)
		}

		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, &DisableMFAResponse{
		Success: true,
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
	//const IMAGE_SIDE_LENGTH = 300
	ctx := r.Context()
	user := getUser(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}


	params := &EnrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read EnrollFactor params: %v", err)
	}

	if (params.FactorType != "totp") && (params.FactorType != "webauthn") {
		return unprocessableEntityError("FactorType needs to be either 'totp' or 'webauthn'")
	}


	// TODO: Figure out way to extract string allow user to pass in timeout and issuer?
	key, err := totp.Generate(totp.GenerateOpts{
                Issuer:      "test@gmail.com",
                AccountName: "test@gmail.com",
    })
	if err != nil {
		return internalServerError("Error generating QR Code secret key").WithInternalError(err)
    }
	var buf bytes.Buffer
    //img, err := key.Image(IMAGE_SIDE_LENGTH, IMAGE_SIDE_LENGTH)
	if err != nil {
		return internalServerError("Error generating QR Code image").WithInternalError(err)
    }
	qrAsString:= base64.StdEncoding.EncodeToString(buf.Bytes())

	// TODO: Generate factor ID
	factor, terr := models.NewFactor(user, params.FactorSimpleName, params.FactorID, params.FactorType, key.Secret())
	if terr != nil {
		return internalServerError("Database error creating factor").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(factor); terr != nil {
			return terr
		}

		return terr
	})
	// Formulate appropriate response to give here
	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID: factor.ID,
		Type: factor.FactorType,
		TOTP: TOTPObject{
			QRCode: fmt.Sprintf("data:img/png;base64,%v", qrAsString),
			Secret: factor.SecretKey,
			URI: key.URL(),
		},
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
