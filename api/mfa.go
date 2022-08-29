package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aaronarduino/goqrsvg"
	"github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pquerna/otp/totp"
	"net/http"
	"strconv"
	"time"
)

type EnrollFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
	Issuer       string `json:"issuer"`
	QRCodeSize   string `json:"qr_code_size"`
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

type VerifyFactorParams struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

type VerifyFactorResponse struct {
	Success string `json:"success"`
}

type UnenrollFactorResponse struct {
	Success string `json:"success"`
}

type UnenrollFactorParams struct {
	Code string `json:"code"`
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	var qrCodeSize int
	const defaultSize = 5
	const factorPrefix = "factor"
	ctx := r.Context()
	user := getUser(ctx)

	params := &EnrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}
	factorType := params.FactorType
	if (factorType != models.TOTP) && (factorType != models.Webauthn) {
		return unprocessableEntityError("FactorType needs to be either 'totp' or 'webauthn'")
	}
	if params.Issuer == "" {
		return unprocessableEntityError("Issuer is required")
	}
	if params.QRCodeSize != "" {
		if i, err := strconv.Atoi(params.QRCodeSize); err == nil {
			qrCodeSize = i
		} else {
			return unprocessableEntityError("Please enter a valid QR Code Size")
		}
	} else if params.QRCodeSize == "" {
		qrCodeSize = defaultSize
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
	s := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.M, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, qrCodeSize)
	qs.StartQrSVG(s)
	qs.WriteQrSVG(s)
	s.End()

	factorID := fmt.Sprintf("%s_%s", factorPrefix, crypto.SecureToken())
	factor, terr := models.NewFactor(user, params.FriendlyName, factorID, params.FactorType, models.FactorDisabledState, key.Secret())
	if terr != nil {
		return internalServerError("Database error creating factor").WithInternalError(err)
	}
	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.EnrollFactorAction, r.RemoteAddr, nil); terr != nil {
			return terr
		}
		return nil
	})
	if terr != nil {
		return terr
	}
	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:   factor.ID,
		Type: factor.FactorType,
		TOTP: TOTPObject{
			// See: https://css-tricks.com/probably-dont-base64-svg/
			QRCode: fmt.Sprintf("data:img/svg+xml;utf-8,%v", w),
			Secret: factor.SecretKey,
			URI:    key.URL(),
		},
	})
}
func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		return internalServerError("Error loading Config").WithInternalError(err)
	}
	user := getUser(ctx)
	factor := getFactor(ctx)
	challenge, terr := models.NewChallenge(factor)
	if err != nil {
		return internalServerError("Database error creating challenge").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     factor.ID,
			"factor_status": factor.Status,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if terr != nil {
		return terr
	}

	creationTime := challenge.CreatedAt
	expiryTime := creationTime.Add(time.Second * time.Duration(globalConfig.MFA.ChallengeExpiryDuration))
	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		ExpiresAt: expiryTime.String(),
	})
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	globalConfig, err := conf.LoadGlobal(configFile)

	params := &VerifyFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Please check the params passed into VerifyFactor: %v", err)
	}

	challenge, err := models.FindChallengeByChallengeID(a.db, params.ChallengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}
	valid := totp.Validate(params.Code, factor.SecretKey)
	if !valid {
		return unauthorizedError("Invalid TOTP code entered")
	}

	hasExpired := time.Now().After(challenge.CreatedAt.Add(time.Second * time.Duration(globalConfig.MFA.ChallengeExpiryDuration)))
	if hasExpired {
		err := a.db.Transaction(func(tx *storage.Connection) error {
			if terr := tx.Destroy(challenge); terr != nil {
				return internalServerError("Database error deleting challenge").WithInternalError(terr)
			}

			return nil
		})
		if err != nil {
			return err
		}

		return expiredChallengeError("%v has expired, please verify against another challenge or create a new challenge.", challenge.ID)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err = models.NewAuditLogEntry(r, tx, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": challenge.ID,
		}); err != nil {
			return err
		}
		if err = challenge.Verify(tx); err != nil {
			return err
		}
		if factor.Status != models.FactorVerifiedState {
			if err = factor.UpdateStatus(tx, models.FactorVerifiedState); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &VerifyFactorResponse{
		Success: fmt.Sprintf("%v", valid),
	})

}

func (a *API) UnenrollFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)

	params := &UnenrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}
	MFAEnabled, err := models.IsMFAEnabled(a.db, user)
	if err != nil {
		return err
	} else if !MFAEnabled {
		return forbiddenError("You do not have a verified factor enrolled")
	}

	valid := totp.Validate(params.Code, factor.SecretKey)
	if valid != true {
		return unauthorizedError("Invalid code entered")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err = tx.Destroy(factor); err != nil {
			return err
		}
		if err = models.NewAuditLogEntry(r, tx, user, models.UnenrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"user_id":   user.ID,
			"factor_id": factor.ID,
		}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &UnenrollFactorResponse{
		Success: fmt.Sprintf("%v", valid),
	})
}
