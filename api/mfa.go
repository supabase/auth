package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pquerna/otp/totp"
	"image/png"
	"net/http"
)

type EnrollFactorParams struct {
	FactorSimpleName string `json:"factor_simple_name"`
	FactorType       string `json:"factor_type"`
	Issuer           string `json:"issuer"`
}

type TOTPObject struct {
	QRCode string
	Secret string
	URI    string
}

type EnrollFactorResponse struct {
	ID        string
	CreatedAt string
	Type      string
	TOTP      TOTPObject
}

type ChallengeFactorParams struct {
	FactorID         string
	FactorSimpleName string
}

type VerifyFactorParams struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        string
	CreatedAt string
	UpdatedAt string
	ExpiresAt string
	FactorID  string
}

type VerifyFactorResponse struct {
	ChallengeID string
	MFAType     string
	Success     string
}


// RecoveryCodesResponse repreesnts a successful recovery code generation response
type RecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.EnableMFA(tx); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)
}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.DisableMFA(tx); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)
}

func (a *API) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) error {
	const numRecoveryCodes = 8
	const recoveryCodeLength = 8
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}
	recoveryCodeModels := []*models.RecoveryCode{}
	var terr error
	var recoveryCode string
	var recoveryCodes []string
	var recoveryCodeModel *models.RecoveryCode
	for i := 0; i < numRecoveryCodes; i++ {
		recoveryCode = crypto.SecureToken(recoveryCodeLength)
		recoveryCodeModel, terr = models.NewRecoveryCode(user, recoveryCode)
		if terr != nil {
			return internalServerError("Error creating recovery code").WithInternalError(terr)
		}
		recoveryCodes = append(recoveryCodes, recoveryCode)
		recoveryCodeModels = append(recoveryCodeModels, recoveryCodeModel)
	}
	terr = a.db.Transaction(func(tx *storage.Connection) error {
		for _, recoveryCodeModel := range recoveryCodeModels {
			if terr = tx.Create(recoveryCodeModel); terr != nil {
				return terr
			}
		}

		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateRecoveryCodesAction, r.RemoteAddr, nil); terr != nil {
			return terr
		}
		return nil
	})
	if terr != nil {
		return terr
	}

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		RecoveryCodes: recoveryCodes,
	})
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	const FACTOR_PREFIX = "factor"
	const IMAGE_SIDE_LENGTH = 300
	var factor *models.Factor
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
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

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      params.Issuer,
		AccountName: params.Issuer,
	})

	if err != nil {
		return internalServerError("Error generating QR Code secret key").WithInternalError(err)
	}
	var buf bytes.Buffer

	// Test with QRCode Encode
	img, err := key.Image(IMAGE_SIDE_LENGTH, IMAGE_SIDE_LENGTH)
	png.Encode(&buf, img)
	if err != nil {
		return internalServerError("Error generating QR Code image").WithInternalError(err)
	}
	qrAsBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	factorID := fmt.Sprintf("%s_%s", FACTOR_PREFIX, crypto.SecureToken())

	factor, terr := models.NewFactor(user, params.FactorSimpleName, factorID, params.FactorType, key.Secret())
	if terr != nil {
		return internalServerError("Database error creating factor").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.EnrollFactorAction, r.RemoteAddr, nil); terr != nil {
			return terr
		}

		return nil
	})

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:   factor.ID,
		Type: factor.FactorType,
		TOTP: TOTPObject{
			QRCode: fmt.Sprintf("data:img/png;base64,%v", qrAsBase64),
			Secret: factor.SecretKey,
			URI:    key.URL(),
		},
	})
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	const CHALLENGE_EXPIRY_DURATION = 300
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}
	var factor *models.Factor
	var err error

	params := &ChallengeFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read EnrollFactor params: %v", err)
	}
	factorID := params.FactorID
	factorSimpleName := params.FactorSimpleName

	if factorID != "" && factorSimpleName != "" {
		return unprocessableEntityError("Only a FactorID or FactorSimpleName should be provided on signup.")
	}

	if factorID != "" {
		factor, err = models.FindFactorByFactorID(a.db, factorID)
	} else if params.FactorSimpleName != "" {
		factor, err = models.FindFactorBySimpleName(a.db, factorSimpleName)
	}
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding factor").WithInternalError(err)
	}

	challenge, terr := models.NewChallenge(factor.ID)
	if terr != nil {
		return internalServerError("Database error creating challenge").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":          params.FactorID,
			"factor_simple_name": params.FactorSimpleName,
		}); terr != nil {
			return terr
		}

		return nil
	})
	creationTime := challenge.CreatedAt.String()
	expiryTimeAsTimestamp, err := time.Parse(time.RFC3339, creationTime)
	if err != nil {
		return internalServerError("Error parsing database timestamp").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		CreatedAt: creationTime,
		ExpiresAt: expiryTimeAsTimestamp.Add(time.Second * CHALLENGE_EXPIRY_DURATION).String(),
		FactorID:  factor.ID,
	})
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}
	params := &VerifyFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read VerifyFactor params: %v", err)
	}
	factor, err := models.FindFactorByChallengeID(a.db, params.ChallengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding factor").WithInternalError(err)
	}
	err = a.db.Transaction(func(tx *storage.Connection) error {

		if err = models.NewAuditLogEntry(tx, instanceID, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": params.ChallengeID,
		}); err != nil {
			return err
		}
		return nil
	})
	valid := totp.Validate(params.Code, factor.SecretKey)
	if valid != true {
		return unauthorizedError("Invalid code entered")
	}

	return sendJSON(w, http.StatusOK, &VerifyFactorResponse{
		ChallengeID: params.ChallengeID,
		MFAType:     factor.FactorType,
		Success:     fmt.Sprintf("%v", valid),
	})

}
