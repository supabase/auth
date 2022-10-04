package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"fmt"
	"net/url"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/utilities"
	"github.com/pquerna/otp/totp"
)

const DefaultQRSize = 3

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
	ID   uuid.UUID  `json:"id"`
	Type string     `json:"type"`
	TOTP TOTPObject `json:TOTP,omitempty"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	Code        string    `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        uuid.UUID `json:"id"`
	ExpiresAt int64     `json:"expires_at"`
}

type UnenrollFactorParams struct {
	Code string `json:"code"`
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config

	params := &EnrollFactorParams{}
	issuer := ""
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}
	factorType := params.FactorType
	if factorType != models.TOTP {
		return unprocessableEntityError("factorType needs to be TOTP")
	}
	if params.Issuer == "" {
		u, err := url.ParseRequestURI(config.SiteURL)
		if err != nil {
			return internalServerError("site url is improperly formatted")
		}
		issuer = u.Host
	} else {
		issuer = params.Issuer
	}

	// Read from DB for certainty
	factors, err := models.FindFactorsByUser(a.db, user)
	if err != nil {
		return internalServerError("error validating number of factors in system").WithInternalError(err)
	}

	if len(factors) >= int(config.MFA.MaxEnrolledFactors) {
		return forbiddenError("Too many enrolled factors exceeds the allowed value, please unenroll to continue")
	}
	numVerifiedFactors := 0

	// TODO: Remove this at v2
	for _, factor := range factors {
		if factor.Status == models.FactorStateVerified {
			numVerifiedFactors += 1
		}

	}
	if numVerifiedFactors >= 1 {
		return forbiddenError("number of enrolled factors exceeds the allowed value, please unenroll to continue")

	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError("error generating QR Code secret key").WithInternalError(err)
	}
	var buf bytes.Buffer
	s := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.M, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(s)
	if err = qs.WriteQrSVG(s); err != nil {
		return internalServerError("error writing to QR Code").WithInternalError(err)
	}
	s.End()

	factor, terr := models.NewFactor(user, params.FriendlyName, params.FactorType, models.FactorStateUnverified, key.Secret())
	if terr != nil {
		return internalServerError("database error creating factor").WithInternalError(err)
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
		Type: models.TOTP,
		TOTP: TOTPObject{
			// See: https://css-tricks.com/probably-dont-base64-svg/
			QRCode: fmt.Sprintf("data:image/svg+xml;utf-8,%v", buf.String()),
			Secret: factor.Secret,
			URI:    key.URL(),
		},
	})
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config

	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)
	challenge, err := models.NewChallenge(factor, ipAddress)
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
		ExpiresAt: expiryTime.Unix(),
	})
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config

	params := &VerifyFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	currentIP := utilities.GetIPAddress(r)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Invalid params for VerifyFactor: %v", err)
	}

	challenge, err := models.FindChallengeByChallengeID(a.db, params.ChallengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return badRequestError("Challenge is not valid")
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
		return badRequestError("%v has expired, please verify against another challenge or create a new challenge.", challenge.ID)
	}

	if valid := totp.Validate(params.Code, factor.Secret); !valid {
		return badRequestError("Invalid TOTP code entered")
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": challenge.ID,
		}); terr != nil {
			return terr
		}
		if terr = challenge.Verify(tx); terr != nil {
			return terr
		}
		if factor.Status != models.FactorStateVerified {
			if terr = factor.UpdateStatus(tx, models.FactorStateVerified); terr != nil {
				return terr
			}
		}
		token, terr = a.issueRefreshToken(ctx, tx, user, models.TOTPSignIn, models.GrantParams{
			FactorID: &factor.ID,
		})
		if terr != nil {
			return terr
		}
		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		if terr = models.InvalidateSessionsWithAALLessThan(tx, user.ID, models.AAL2.String()); terr != nil {
			return internalServerError("Failed to update sessions. %s", terr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin(string(models.MFACodeLoginAction), user.ID)

	return sendJSON(w, http.StatusOK, token)

}

func (a *API) UnenrollFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	session := getSession(ctx)

	params := &UnenrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err = jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError(err.Error())
	}

	if factor.Status == models.FactorStateVerified {
		valid := totp.Validate(params.Code, factor.Secret)
		if !valid {
			return unauthorizedError("Invalid code entered")
		}
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr := tx.Destroy(factor); terr != nil {
			return err
		}
		if terr = models.NewAuditLogEntry(r, tx, user, models.UnenrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"factor_id":  factor.ID,
			"session_id": session.ID,
		}); terr != nil {
			return terr
		}
		if terr = models.InvalidateOtherFactorAssociatedSessions(tx, session.ID, user.ID, factor.ID); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}
