package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/gofrs/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/supabase/auth/internal/hooks"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
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

	if params.FactorType != models.TOTP {
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
		if factor.IsVerified() {
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
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}
	var buf bytes.Buffer
	svgData := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.M, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(svgData)
	if err = qs.WriteQrSVG(svgData); err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
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

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		ExpiresAt: challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) runHook(ctx context.Context, name string, input, output any) ([]byte, error) {
	db := a.db.WithContext(ctx)

	request, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}

	var response []byte
	if err := db.Transaction(func(tx *storage.Connection) error {
		// We rely on Postgres timeouts to ensure the function doesn't overrun
		if terr := tx.RawQuery(fmt.Sprintf("set local statement_timeout TO '%d';", hooks.DefaultTimeout)).Exec(); terr != nil {
			return terr
		}

		if terr := tx.RawQuery(fmt.Sprintf("select %s(?);", name), request).First(&response); terr != nil {
			return terr
		}

		// reset the timeout
		if terr := tx.RawQuery("set local statement_timeout TO default;").Exec(); terr != nil {
			return terr
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(response, output); err != nil {
		return response, err
	}

	return response, nil
}

func (a *API) invokeHook(ctx context.Context, input, output any) error {
	config := a.config
	switch input.(type) {
	case *hooks.MFAVerificationAttemptInput:
		hookOutput, ok := output.(*hooks.MFAVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.MFAVerificationAttemptOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.MFAVerificationAttempt.HookName, input, output); err != nil {
			return internalServerError("Error invoking MFA verification hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}

		return nil
	case *hooks.PasswordVerificationAttemptInput:
		hookOutput, ok := output.(*hooks.PasswordVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.PasswordVerificationAttemptOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.PasswordVerificationAttempt.HookName, input, output); err != nil {
			return internalServerError("Error invoking password verification hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}

		return nil
	case *hooks.CustomAccessTokenInput:
		hookOutput, ok := output.(*hooks.CustomAccessTokenOutput)
		if !ok {
			panic("output should be *hooks.CustomAccessTokenOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.CustomAccessToken.HookName, input, output); err != nil {
			return internalServerError("Error invoking access token hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}
		if err := validateTokenClaims(hookOutput.Claims); err != nil {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: err.Error(),
			}

			return httpError
		}
		return nil

	default:
		panic("unknown hook input type")
	}
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

	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
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

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
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

	valid := totp.Validate(params.Code, factor.Secret)

	if config.Hook.MFAVerificationAttempt.Enabled {
		input := hooks.MFAVerificationAttemptInput{
			UserID:   user.ID,
			FactorID: factor.ID,
			Valid:    valid,
		}

		output := hooks.MFAVerificationAttemptOutput{}

		err := a.invokeHook(ctx, &input, &output)
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

			return forbiddenError(output.Message)
		}
	}
	if !valid {
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
		return badRequestError("AAL2 required to unenroll verified factor")
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
