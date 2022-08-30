package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aaronarduino/goqrsvg"
	"github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pquerna/otp/totp"
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

type StepUpLoginParams struct {
	ChallengeID  string `json:"challenge_id"`
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
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
	qs := goqrsvg.NewQrSVG(qrCode, models.DefaultQRSize)
	qs.StartQrSVG(s)
	err = qs.WriteQrSVG(s)
	if err != nil {
		return internalServerError("Error writing to QR Code").WithInternalError(err)
	}

	s.End()

	factorID := fmt.Sprintf("%s_%s", factorPrefix, crypto.SecureToken())
	factor, terr := models.NewFactor(user, params.FriendlyName, factorID, params.FactorType, models.FactorUnverifiedState, key.Secret())
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
			QRCode: fmt.Sprintf("data:img/svg+xml;utf-8,%v", &buf),
			Secret: factor.SecretKey,
			URI:    key.URL(),
		},
	})
}
func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config

	user := getUser(ctx)
	factor := getFactor(ctx)
	challenge, err := models.NewChallenge(factor)
	if err != nil {
		return internalServerError("Database error creating challenge").WithInternalError(err)
	}

	terr := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(challenge); terr != nil {
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
	expiryTime := creationTime.Add(time.Second * time.Duration(config.MFA.ChallengeExpiryDuration))
	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		ExpiresAt: expiryTime.String(),
	})
}

// TODO(Joel): Move over other supporting changes from other branch. Don't use until properly tested.
func (a *API) StepUpLogin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	user := getUser(ctx)
	factor := getFactor(ctx)

	if factor.Status != models.FactorVerifiedState {
		return unprocessableEntityError("Please attempt a login with a verified factor")
	}

	params := &StepUpLoginParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Please check the params passed into StepupLogin: %v", err)
	}
	if params.Code != "" && params.RecoveryCode != "" {
		return unprocessableEntityError("Please attempt a login with only one of Code or Recovery Code'")
	}

	if params.Code != "" {
		// TODO(suggest): Either reorganize to token grant style case statement with types OR dump this into models
		challenge, err := models.FindChallengeByChallengeID(a.db, params.ChallengeID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return notFoundError(err.Error())
			}
			return internalServerError("Database error finding Challenge").WithInternalError(err)
		}
		hasExpired := time.Now().After(challenge.CreatedAt.Add(time.Second * time.Duration(config.MFA.ChallengeExpiryDuration)))
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
		valid := totp.Validate(params.Code, factor.SecretKey)
		if !valid {
			return unauthorizedError("Invalid code entered")
		}
	} else if params.RecoveryCode != "" {
		// TODO(suggest): Shorten session duration for sessions arising from recovery code
		err := a.db.Transaction(func(tx *storage.Connection) error {
			rc, terr := models.IsRecoveryCodeValid(tx, user, params.RecoveryCode)
			if terr != nil {
				return terr
			}
			if rc.RecoveryCode == params.RecoveryCode {
				terr = rc.Consume(tx)
				if terr != nil {
					return terr
				}
			} else {
				return unauthorizedError("Invalid code entered")
			}

			return nil

		})
		if err != nil {
			return err
		}
		return unauthorizedError("Invalid code entered")
	}
	var token *AccessTokenResponse

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.MFALoginAction, "", nil); terr != nil {
			return terr
		}
		// TODO(joel): Reinstate the TOTP claim when we add the claims logic to all endpoints
		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("token", user.ID)
	// if user.IsFirstMFALogin(){
	//  // Wrap this in a transaction
	//  recoveryCodes, err := models.GenerateRecoveryCodesBatch()
	//	return sendJSON(w, http.StatusOK, StepUpLoginResponse{
	//	     token: token
	//	     recovery_code: recoveryCodes
	//	 })
	// }

	return sendJSON(w, http.StatusOK, token)
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config

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

	hasExpired := time.Now().After(challenge.CreatedAt.Add(time.Second * time.Duration(config.MFA.ChallengeExpiryDuration)))
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
