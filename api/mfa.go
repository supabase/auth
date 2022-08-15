package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/metering"
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

type VerifyFactorParams struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

type StepUpLoginParams struct {
	ChallengeID  string `json:"challenge_id"`
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
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
	const factorPrefix = "factor"
	const imageSideLength = 300
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)

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
	ctx := r.Context()
	config := a.getConfig(ctx)
	user := getUser(ctx)
	factor := getFactor(ctx)
	instanceID := getInstanceID(ctx)
	challenge, terr := models.NewChallenge(factor)
	if terr != nil {
		return internalServerError("Database error creating challenge").WithInternalError(terr)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
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

func (a *API) StepUpLogin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	user := getUser(ctx)
	factor := getFactor(ctx)
	instanceID := getInstanceID(ctx)

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

		// TODO: Check that the recovery code exists for a user and that it hasn't been used prior
		return unauthorizedError("Invalid code entered")
	}
	var token *AccessTokenResponse

	// Here, after we verify and if it succeds we return the access token
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.MFALoginAction, "", nil); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user, "totp")
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
	metering.RecordLogin("token", user.ID, instanceID)
	// TODO: branching logic for recovery codes
	return sendJSON(w, http.StatusOK, token)
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	config := a.getConfig(ctx)
	user := getUser(ctx)
	factor := getFactor(ctx)
	instanceID := getInstanceID(ctx)

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
	if challenge.VerifiedAt != nil {
		return badRequestError("Challenge has already been verified")
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
		if err = models.NewAuditLogEntry(tx, instanceID, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": params.ChallengeID,
		}); err != nil {
			return err
		}
		if err = challenge.Verify(a.db); err != nil {
			return err
		}
		if factor.Status != models.FactorVerifiedState {
			if err = factor.UpdateStatus(a.db, models.FactorVerifiedState); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	valid := totp.Validate(params.Code, factor.SecretKey)
	if !valid {
		return unauthorizedError("Invalid TOTP code entered")
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
	instanceID := getInstanceID(ctx)

	params := &UnenrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}

	valid := totp.Validate(params.Code, factor.SecretKey)
	if valid != true {
		return unauthorizedError("Invalid code entered")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err = tx.Destroy(factor); err != nil {
			return err
		}
		if err = models.NewAuditLogEntry(tx, instanceID, user, models.UnenrollFactorAction, r.RemoteAddr, map[string]interface{}{
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
