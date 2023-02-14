package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"net/url"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/utilities"
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
	TOTP TOTPObject `json:"totp,omitempty"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	Code        string    `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        uuid.UUID `json:"id"`
	ExpiresAt int64     `json:"expires_at"`
}

type UnenrollFactorResponse struct {
	ID uuid.UUID `json:"id"`
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config

	params := &EnrollFactorParams{}
	issuer := ""
	body, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("invalid body: unable to parse JSON").WithInternalError(err)
	}

	if user.IsSSOUser {
		return unprocessableEntityError("MFA enrollment only supported for non-SSO users at this time")
	}

	factorType := params.FactorType
	if factorType != models.TOTP {
		return badRequestError("factor_type needs to be totp")
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
		return forbiddenError("Enrolled factors exceed allowed limit, unenroll to continue")
	}
	numVerifiedFactors := 0

	for _, factor := range factors {
		if factor.Status == models.FactorStateVerified.String() {
			numVerifiedFactors += 1
		}
	}
	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return forbiddenError("Maximum number of enrolled factors reached, unenroll to continue")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError("error generating QR Code secret key").WithInternalError(err)
	}
	var buf bytes.Buffer
	svgData := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.M, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(svgData)
	if err = qs.WriteQrSVG(svgData); err != nil {
		return internalServerError("error writing to QR Code").WithInternalError(err)
	}
	svgData.End()

	factor, err := models.NewFactor(user, params.FriendlyName, params.FactorType, models.FactorStateUnverified, key.Secret())
	if err != nil {
		return internalServerError("database error creating factor").WithInternalError(err)
	}
	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.EnrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id": factor.ID,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:   factor.ID,
		Type: models.TOTP,
		TOTP: TOTPObject{
			// See: https://css-tricks.com/probably-dont-base64-svg/
			QRCode: buf.String(),
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

	err = a.db.Transaction(func(tx *storage.Connection) error {
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
	if err != nil {
		return err
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
	currentIP := utilities.GetIPAddress(r)

	body, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("invalid body: unable to parse JSON").WithInternalError(err)
	}

	if factor.UserID != user.ID {
		return internalServerError("user needs to own factor to verify")
	}

	challenge, err := models.FindChallengeByChallengeID(a.db, params.ChallengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return badRequestError("Challenge and verify IP addresses mismatch")
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
		return badRequestError("%v has expired, verify against another challenge or create a new challenge.", challenge.ID)
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
		if factor.Status != models.FactorStateVerified.String() {
			if terr = factor.UpdateStatus(tx, models.FactorStateVerified); terr != nil {
				return terr
			}
		}
		user, terr = models.FindUserByID(tx, user.ID)
		if terr != nil {
			return terr
		}
		token, terr = a.updateMFASessionAndClaims(r, tx, user, models.TOTPSignIn, models.GrantParams{
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
		if terr = models.DeleteUnverifiedFactors(tx, user); terr != nil {
			return internalServerError("Error removing unverified factors. %s", terr)
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

	if factor.Status == models.FactorStateVerified.String() && session.GetAAL() != models.AAL2.String() {
		return badRequestError("AAL2 required to unenroll verified factor")
	}
	if factor.UserID != user.ID {
		return internalServerError("user must own factor to unenroll")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr := tx.Destroy(factor); terr != nil {
			return terr
		}
		if terr = models.NewAuditLogEntry(r, tx, user, models.UnenrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     factor.ID,
			"factor_status": factor.Status,
			"session_id":    session.ID,
		}); terr != nil {
			return terr
		}
		if terr = factor.DowngradeSessionsToAAL1(tx); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &UnenrollFactorResponse{
		ID: factor.ID,
	})
}
