package api

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/gofrs/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/crypto"
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
	Phone        string `json:"phone"`
}

type TOTPObject struct {
	QRCode string `json:"qr_code,omitempty"`
	Secret string `json:"secret,omitempty"`
	URI    string `json:"uri,omitempty"`
}

type EnrollFactorResponse struct {
	ID           uuid.UUID  `json:"id"`
	Type         string     `json:"type"`
	FriendlyName string     `json:"friendly_name"`
	TOTP         TOTPObject `json:"totp,omitempty"`
	Phone        string     `json:"phone,omitempty"`
}

type ChallengeFactorParams struct {
	Channel string `json:"channel"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	Code        string    `json:"code"`
}

type ChallengeFactorResponse struct {
	ID        uuid.UUID `json:"id"`
	Type      string    `json:"type"`
	ExpiresAt int64     `json:"expires_at"`
}

type UnenrollFactorResponse struct {
	ID uuid.UUID `json:"id"`
}

const (
	QRCodeGenerationErrorMessage = "Error generating QR Code"
)

func (a *API) enrollPhoneFactor(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	ctx := r.Context()
	config := a.config
	user := getUser(ctx)
	session := getSession(ctx)
	db := a.db.WithContext(ctx)
	if params.Phone == "" {
		return badRequestError(ErrorCodeValidationFailed, "Phone number required to enroll Phone factor")
	}

	phone, err := validatePhone(params.Phone)
	if err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Invalid phone number format (E.164 required)")
	}
	factors := user.Factors

	factorCount := len(factors)
	numVerifiedFactors := 0
	if err := models.DeleteExpiredFactors(db, config.MFA.FactorExpiryDuration); err != nil {
		return err
	}
	var factorsToDelete []models.Factor
	for _, factor := range user.Factors {
		switch {
		case factor.FriendlyName == params.FriendlyName:
			return unprocessableEntityError(
				ErrorCodeMFAFactorNameConflict,
				fmt.Sprintf("A factor with the friendly name %q for this user already exists", factor.FriendlyName),
			)

		case factor.IsPhoneFactor():
			if factor.Phone.String() == phone {
				if factor.IsVerified() {
					return unprocessableEntityError(
						ErrorCodeVerifiedFactorExists,
						"A verified phone factor already exists, unenroll the existing factor to continue",
					)
				} else if factor.IsUnverified() {
					factorsToDelete = append(factorsToDelete, factor)
				}

			}

		case factor.IsVerified():
			numVerifiedFactors++
		}
	}

	if err := db.Destroy(&factorsToDelete); err != nil {
		return internalServerError("Database error deleting unverified phone factors").WithInternalError(err)
	}

	if factorCount >= int(config.MFA.MaxEnrolledFactors) {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && !session.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}
	factor := models.NewPhoneFactor(user, phone, params.FriendlyName)
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.EnrollFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":   factor.ID,
			"factor_type": factor.FactorType,
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
		Type:         models.Phone,
		FriendlyName: factor.FriendlyName,
		Phone:        params.Phone,
	})
}

func (a *API) enrollTOTPFactor(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	ctx := r.Context()
	user := getUser(ctx)
	db := a.db.WithContext(ctx)
	config := a.config
	session := getSession(ctx)
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
	if err := models.DeleteExpiredFactors(db, config.MFA.FactorExpiryDuration); err != nil {
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
	var factor *models.Factor
	var buf bytes.Buffer
	var key *otp.Key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}

	svgData := svg.New(&buf)
	qrCode, _ := qr.Encode(key.String(), qr.H, qr.Auto)
	qs := goqrsvg.NewQrSVG(qrCode, DefaultQRSize)
	qs.StartQrSVG(svgData)
	if err = qs.WriteQrSVG(svgData); err != nil {
		return internalServerError(QRCodeGenerationErrorMessage).WithInternalError(err)
	}
	svgData.End()

	factor = models.NewTOTPFactor(user, params.FriendlyName)
	if err := factor.SetSecret(key.Secret(), config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
		return err
	}

	err = db.Transaction(func(tx *storage.Connection) error {
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
			Secret: key.Secret(),
			URI:    key.URL(),
		},
	})
}

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

	switch params.FactorType {
	case models.Phone:
		if !config.MFA.Phone.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneEnrollDisabled, "MFA enroll is disabled for Phone")
		}
		return a.enrollPhoneFactor(w, r, params)
	case models.TOTP:
		if !config.MFA.TOTP.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, "MFA enroll is disabled for TOTP")
		}
		return a.enrollTOTPFactor(w, r, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp or phone")
	}

}

func (a *API) challengePhoneFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)
	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)
	params := &ChallengeFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	channel := params.Channel
	if channel == "" {
		channel = sms_provider.SMSProvider
	}
	if !sms_provider.IsValidMessageChannel(channel, config) {
		return badRequestError(ErrorCodeValidationFailed, InvalidChannelError)
	}

	if factor.IsPhoneFactor() && factor.LastChallengedAt != nil {
		if !factor.LastChallengedAt.Add(config.MFA.Phone.MaxFrequency).Before(time.Now()) {
			return tooManyRequestsError(ErrorCodeOverSMSSendRateLimit, generateFrequencyLimitErrorMessage(factor.LastChallengedAt, config.MFA.Phone.MaxFrequency))
		}
	}
	otp, err := crypto.GenerateOtp(config.MFA.Phone.OtpLength)
	if err != nil {
		panic(err)
	}
	challenge, err := factor.CreatePhoneChallenge(ipAddress, otp, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey)
	if err != nil {
		return internalServerError("error creating SMS Challenge")
	}

	message, err := generateSMSFromTemplate(config.MFA.Phone.SMSTemplate, otp)
	if err != nil {
		return internalServerError("error generating sms template").WithInternalError(err)
	}

	if config.Hook.SendSMS.Enabled {
		input := hooks.SendSMSInput{
			User: user,
			SMS: hooks.SMS{
				OTP:     otp,
				SMSType: "mfa",
			},
		}
		output := hooks.SendSMSOutput{}
		err := a.invokeHook(a.db, r, &input, &output)
		if err != nil {
			return internalServerError("error invoking hook")
		}
	} else {
		smsProvider, err := sms_provider.GetSmsProvider(*config)
		if err != nil {
			return internalServerError("Failed to get SMS provider").WithInternalError(err)
		}
		// We omit messageID for now, can consider reinstating if there are requests.
		if _, err = smsProvider.SendMessage(factor.Phone.String(), message, channel, otp); err != nil {
			return internalServerError("error sending message").WithInternalError(err)
		}
	}
	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := factor.WriteChallengeToDatabase(tx, challenge); terr != nil {
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
		Type:      factor.FactorType,
		ExpiresAt: challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) challengeTOTPFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)

	challenge := factor.CreateChallenge(ipAddress)

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := factor.WriteChallengeToDatabase(tx, challenge); terr != nil {
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
		Type:      factor.FactorType,
		ExpiresAt: challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	factor := getFactor(ctx)

	switch factor.FactorType {
	case models.Phone:
		if !config.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneEnrollDisabled, "MFA verification is disabled for Phone")
		}
		return a.challengePhoneFactor(w, r)

	case models.TOTP:
		if !config.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, "MFA verification is disabled for TOTP")
		}
		return a.challengeTOTPFactor(w, r)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be TOTP or Phone")
	}

}

func (a *API) verifyTOTPFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config
	db := a.db.WithContext(ctx)
	currentIP := utilities.GetIPAddress(r)

	challenge, err := factor.FindChallengeByID(db, params.ChallengeID)
	if err != nil && models.IsNotFoundError(err) {
		return notFoundError(ErrorCodeMFAFactorNotFound, "MFA factor with the provided challenge ID not found")
	} else if err != nil {
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	// Ambiguous so as not to leak whether there is a verified challenge
	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return unprocessableEntityError(ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch")
	}

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
		if err := db.Destroy(challenge); err != nil {
			return internalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return unprocessableEntityError(ErrorCodeMFAChallengeExpired, "MFA challenge %v has expired, verify against another challenge or create a new challenge.", challenge.ID)
	}

	secret, shouldReEncrypt, err := factor.GetSecret(config.Security.DBEncryption.DecryptionKeys, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID)
	if err != nil {
		return internalServerError("Database error verifying MFA TOTP secret").WithInternalError(err)
	}

	valid, verr := totp.ValidateCustom(params.Code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if config.Hook.MFAVerificationAttempt.Enabled {
		input := hooks.MFAVerificationAttemptInput{
			UserID:   user.ID,
			FactorID: factor.ID,
			Valid:    valid,
		}

		output := hooks.MFAVerificationAttemptOutput{}
		err := a.invokeHook(nil, r, &input, &output)
		if err != nil {
			return err
		}

		if output.Decision == hooks.HookRejection {
			if err := models.Logout(db, user.ID); err != nil {
				return err
			}

			if output.Message == "" {
				output.Message = hooks.DefaultMFAHookRejectionMessage
			}

			return forbiddenError(ErrorCodeMFAVerificationRejected, output.Message)
		}
	}
	if !valid {
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt {
			if err := factor.SetSecret(secret, true, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
				return err
			}

			if err := db.UpdateOnly(factor, "secret"); err != nil {
				return err
			}
		}
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid TOTP code entered").WithInternalError(verr)
	}

	var token *AccessTokenResponse

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": challenge.ID,
			"factor_type":  factor.FactorType,
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
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt {
			es, terr := crypto.NewEncryptedString(factor.ID.String(), []byte(secret), config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey)
			if terr != nil {
				return terr
			}

			factor.Secret = es.String()
			if terr := tx.UpdateOnly(factor, "secret"); terr != nil {
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
		if terr = models.DeleteUnverifiedFactors(tx, user, factor.FactorType); terr != nil {
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

func (a *API) verifyPhoneFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	ctx := r.Context()
	config := a.config
	user := getUser(ctx)
	factor := getFactor(ctx)
	db := a.db.WithContext(ctx)
	currentIP := utilities.GetIPAddress(r)

	challenge, err := factor.FindChallengeByID(db, params.ChallengeID)
	if err != nil && models.IsNotFoundError(err) {
		return notFoundError(ErrorCodeMFAFactorNotFound, "MFA factor with the provided challenge ID not found")
	} else if err != nil {
		return internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return unprocessableEntityError(ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch")
	}

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
		if err := db.Destroy(challenge); err != nil {
			return internalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return unprocessableEntityError(ErrorCodeMFAChallengeExpired, "MFA challenge %v has expired, verify against another challenge or create a new challenge.", challenge.ID)
	}
	var valid bool
	var otpCode string
	var shouldReEncrypt bool
	var err error
	if config.Sms.IsTwilioVerifyProvider() {
		smsProvider, _ := sms_provider.GetSmsProvider(*config)
		if err := smsProvider.(*sms_provider.TwilioVerifyProvider).VerifyOTP(factor.Phone.String(), nonce); err != nil {
			return forbiddenError(ErrorCodeOTPExpired, "Token has expired or is invalid").WithInternalError(err)
		}
		valid = true
	} else {
		otpCode, shouldReEncrypt, err = challenge.GetOtpCode(config.Security.DBEncryption.DecryptionKeys, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID)
		if err != nil {
			return internalServerError("Database error verifying MFA TOTP secret").WithInternalError(err)
		}
		valid = subtle.ConstantTimeCompare([]byte(otpCode), []byte(params.Code)) == 1
	}
	if config.Hook.MFAVerificationAttempt.Enabled {
		input := hooks.MFAVerificationAttemptInput{
			UserID:     user.ID,
			FactorID:   factor.ID,
			FactorType: factor.FactorType,
			Valid:      valid,
		}

		output := hooks.MFAVerificationAttemptOutput{}
		err := a.invokeHook(nil, r, &input, &output)
		if err != nil {
			return err
		}

		if output.Decision == hooks.HookRejection {
			if err := models.Logout(db, user.ID); err != nil {
				return err
			}

			if output.Message == "" {
				output.Message = hooks.DefaultMFAHookRejectionMessage
			}

			return forbiddenError(ErrorCodeMFAVerificationRejected, output.Message)
		}
	}
	if !valid {
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt {
			if err := challenge.SetOtpCode(otpCode, true, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
				return err
			}

			if err := db.UpdateOnly(challenge, "otp_code"); err != nil {
				return err
			}
		}
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid MFA Phone code entered")
	}

	var token *AccessTokenResponse

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.VerifyFactorAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":    factor.ID,
			"challenge_id": challenge.ID,
			"factor_type":  factor.FactorType,
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

		token, terr = a.updateMFASessionAndClaims(r, tx, user, models.MFAPhone, models.GrantParams{
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
		if terr = models.DeleteUnverifiedFactors(tx, user, factor.FactorType); terr != nil {
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

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	factor := getFactor(ctx)
	config := a.config

	params := &VerifyFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.Code == "" {
		return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
	}

	switch factor.FactorType {
	case models.Phone:
		if !config.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneEnrollDisabled, "MFA verification is disabled for Phone")
		}

		return a.verifyPhoneFactor(w, r, params)
	case models.TOTP:
		if !config.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, "MFA verification is disabled for TOTP")
		}
		return a.verifyTOTPFactor(w, r, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be TOTP or Phone")
	}

}

func (a *API) UnenrollFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	session := getSession(ctx)
	db := a.db.WithContext(ctx)

	if factor == nil || session == nil || user == nil {
		return internalServerError("A valid session and factor are required to unenroll a factor")
	}

	if factor.IsVerified() && !session.IsAAL2() {
		return unprocessableEntityError(ErrorCodeInsufficientAAL, "AAL2 required to unenroll verified factor")
	}

	err = db.Transaction(func(tx *storage.Connection) error {
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
