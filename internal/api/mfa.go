package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/clanwyse/halo/internal/hooks"
	"github.com/clanwyse/halo/internal/metering"
	"github.com/clanwyse/halo/internal/models"
	"github.com/clanwyse/halo/internal/storage"
	"github.com/clanwyse/halo/internal/utilities"
	"github.com/gofrs/uuid"
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
	ID           uuid.UUID  `json:"id"`
	Type         string     `json:"type"`
	FriendlyName string     `json:"friendly_name"`
	TOTP         TOTPObject `json:"totp,omitempty"`
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

const (
	InvalidFactorOwnerErrorMessage = "Factor does not belong to user"
	QRCodeGenerationErrorMessage   = "Error generating QR Code"
)

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	config := a.config

	if session == nil || user == nil {
		return internalServerError("A valid session and a registered user are required to enroll a factor")
	}

	params := &EnrollFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.FactorType != models.TOTP {
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp")
	}

	issuer := ""
	if params.Issuer == "" {
		u, err := url.ParseRequestURI(config.SiteURL)
		if err != nil {
			return internalServerError("site url is improperly formatted")
		}
		issuer = u.Host
	} else {
		issuer = params.Issuer
	}

	factors := user.Factors

	factorCount := len(factors)
	numVerifiedFactors := 0
	if err := models.DeleteExpiredFactors(a.db, config.MFA.FactorExpiryDuration); err != nil {
		return err
	}

	for _, factor := range factors {
		if factor.IsVerified() {
			numVerifiedFactors += 1
		}
	}

	if factorCount >= int(config.MFA.MaxEnrolledFactors) {
		return forbiddenError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return forbiddenError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && !session.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}

	var buf bytes.Buffer
	svgData := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.H, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(svgData)
	if err = qs.WriteQrSVG(svgData); err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}
	svgData.End()

	factor := models.NewFactor(user, params.FriendlyName, params.FactorType, models.FactorStateUnverified, key.Secret())

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			pgErr := utilities.NewPostgresError(terr)
			if pgErr.IsUniqueConstraintViolated() {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict, fmt.Sprintf("A factor with the friendly name %q for this user likely already exists", factor.FriendlyName))
			}
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
		ID:           factor.ID,
		Type:         models.TOTP,
		FriendlyName: factor.FriendlyName,
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
	challenge := models.NewChallenge(factor, ipAddress)

	if err := a.db.Transaction(func(tx *storage.Connection) error {
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
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		ExpiresAt: challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config

	params := &VerifyFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	currentIP := utilities.GetIPAddress(r)

	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
	}

	challenge, err := models.FindChallengeByID(a.db, params.ChallengeID)
	if err != nil && models.IsNotFoundError(err) {
		return notFoundError(ErrorCodeMFAFactorNotFound, "MFA factor with the provided challenge ID not found")
	} else if err != nil {
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return unprocessableEntityError(ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch")
	}

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
		if err := a.db.Destroy(challenge); err != nil {
			return internalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return unprocessableEntityError(ErrorCodeMFAChallengeExpired, "MFA challenge %v has expired, verify against another challenge or create a new challenge.", challenge.ID)
	}

	valid := totp.Validate(params.Code, factor.Secret)

	if config.Hook.MFAVerificationAttempt.Enabled {
		input := hooks.MFAVerificationAttemptInput{
			UserID:   user.ID,
			FactorID: factor.ID,
			Valid:    valid,
		}

		output := hooks.MFAVerificationAttemptOutput{}

		err := a.invokeHook(ctx, nil, &input, &output)
		if err != nil {
			return err
		}

		if output.Decision == hooks.HookRejection {
			if err := models.Logout(a.db, user.ID); err != nil {
				return err
			}

			if output.Message == "" {
				output.Message = hooks.DefaultMFAHookRejectionMessage
			}

			return forbiddenError(ErrorCodeMFAVerificationRejected, output.Message)
		}
	}
	if !valid {
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid TOTP code entered")
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
		if !factor.IsVerified() {
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
	if factor == nil || session == nil || user == nil {
		return internalServerError("A valid session and factor are required to unenroll a factor")
	}

	if factor.IsVerified() && !session.IsAAL2() {
		return unprocessableEntityError(ErrorCodeInsufficientAAL, "AAL2 required to unenroll verified factor")
	}
	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
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
