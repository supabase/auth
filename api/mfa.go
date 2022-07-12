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
	"time"
)

type EnrollFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
	Issuer       string `json:"issuer"`
}

type TOTPObject struct {
	QRCode string `json:"qr_code"`
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type EnrollFactorResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Type      string `json:"type"`
	TOTP      TOTPObject
}

type ChallengeFactorParams struct {
	FactorID     string `json:"factor_id"`
	FriendlyName string `json:"friendly_name"`
}

type ChallengeFactorResponse struct {
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	ExpiresAt    string `json:"expires_at"`
	FactorID     string `json:"factor_id"`
	FriendlyName string `json:"friendly_name"`
}

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
		return forbiddenError(MFANotEnabledMsg)
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
	const factorPrefix = "factor"
	const imageSideLength = 300
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return forbiddenError(MFANotEnabledMsg)
	}

	params := &EnrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}
	if (params.FactorType != "totp") && (params.FactorType != "webauthn") {
		return unprocessableEntityError("FactorType needs to be either 'totp' or 'webauthn'")
	}
	// TODO(Joel): Review this portion when email is no longer a primary key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      params.Issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError("Error generating QR Code secret key").WithInternalError(err)
	}
	var buf bytes.Buffer
	img, err := key.Image(imageSideLength, imageSideLength)
	png.Encode(&buf, img)
	if err != nil {
		return internalServerError("Error generating QR Code image").WithInternalError(err)
	}
	qrAsBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	factorID := fmt.Sprintf("%s_%s", factorPrefix, crypto.SecureToken())
	// TODO(Joel): Convert constants into an Enum in future
	factor, terr := models.NewFactor(user, params.FriendlyName, factorID, params.FactorType, models.FactorDisabledState, key.Secret())
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
	const challengeExpiryDuration = 300
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return forbiddenError(MFANotEnabledMsg)
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
	friendlyName := params.FriendlyName

	if factorID != "" && friendlyName != "" {
		return unprocessableEntityError("Only a FactorID or FactorSimpleName should be provided on signup.")
	}

	if factorID != "" {
		factor, err = models.FindFactorByFactorID(a.db, factorID)
	} else if friendlyName != "" {
		factor, err = models.FindFactorByFriendlyName(a.db, friendlyName)
	} else {
		return unprocessableEntityError("Either FactorID or FactorSimpleName should be provided on signup.")
	}
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding factor").WithInternalError(err)
	}

	challenge, terr := models.NewChallenge(factor)
	if terr != nil {
		return internalServerError("Database error creating challenge").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     params.FactorID,
			"friendly_name": params.FriendlyName,
			"factor_status": factor.Status,
		}); terr != nil {
			return terr
		}

		return nil
	})
	creationTime := challenge.CreatedAt
	if err != nil {
		return internalServerError("Error parsing database timestamp").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:           challenge.ID,
		CreatedAt:    creationTime.String(),
		ExpiresAt:    creationTime.Add(time.Second * challengeExpiryDuration).String(),
		FactorID:     factor.ID,
		FriendlyName: factor.FriendlyName,
	})
}
