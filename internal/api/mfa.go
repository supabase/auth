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
	wbnprotocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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

const (
	ErrorMsgMFAEnrollDisabled = "MFA enrollment is disabled for %q"
	ErrorMsgMFAVerifyDisabled = "MFA verification is disabled for %q"
)

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
	ID           uuid.UUID                       `json:"id"`
	ChallengeID  *uuid.UUID                      `json:"challenge_id,omitempty"`
	Type         string                          `json:"type"`
	FriendlyName string                          `json:"friendly_name"`
	TOTP         TOTPObject                      `json:"totp,omitempty"`
	Phone        string                          `json:"phone,omitempty"`
	WebAuthn     *wbnprotocol.CredentialCreation `json:"web_authn,omitempty"`
}

type ChallengeFactorParams struct {
	Channel string `json:"channel,omitempty"`
}

type WebAuthnVerifyParams struct {
	// CreationResponse is the response received from the navigator.credentials.create() API.
	CreationResponse *wbnprotocol.CredentialCreationResponse `json:"creation_response,omitempty"`

	// GetResponse is the response received from the navigator.credentials.get() API, i.e. the `publicKey.response`.
	GetResponse *wbnprotocol.CredentialAssertionResponse `json:"get_response,omitempty"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID             `json:"challenge_id,omitempty"`
	Code        string                `json:"code,omitempty"`
	WebAuthn    *WebAuthnVerifyParams `json:"web_authn,omitempty"`
}

type ChallengeFactorResponse struct {
	ID        uuid.UUID `json:"id"`
	ExpiresAt int64     `json:"expires_at"`

	WebAuthn *wbnprotocol.CredentialAssertion `json:"web_authn,omitempty"`
}

type UnenrollFactorResponse struct {
	ID uuid.UUID `json:"id"`
}

const (
	InvalidFactorOwnerErrorMessage = "Factor does not belong to user"
	QRCodeGenerationErrorMessage   = "Error generating QR Code"
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

	// TODO: Move this to a separate PR. Possibly, move this entire block to enroll so it covers all factors.
	for _, factor := range user.Factors {
		if factor.FriendlyName == params.FriendlyName {
			return unprocessableEntityError(ErrorCodeMFAFactorNameConflict, fmt.Sprintf("A factor with the friendly name %q for this user likely already exists", factor.FriendlyName))
		}
	}

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
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && !session.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}
	factor := models.NewPhoneFactor(user, phone, params.FriendlyName, params.FactorType, models.FactorStateUnverified)
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			pgErr := utilities.NewPostgresError(terr)
			if pgErr.IsUniqueConstraintViolated() {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict, fmt.Sprintf("A factor with the friendly name %q for this user likely already exists", factor.FriendlyName))
			}
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
		Phone:        string(factor.Phone),
	})
}

func (a *API) enrollWebAuthnFactor(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config
	authSession := getSession(ctx)

	db := a.db.WithContext(ctx)
	ipAddress := utilities.GetIPAddress(r)
	numVerifiedFactors := 0
	factors := user.Factors

	for _, factor := range factors {
		if factor.FriendlyName == params.FriendlyName {
			return unprocessableEntityError(ErrorCodeMFAFactorNameConflict, fmt.Sprintf("A factor with the friendly name %q for this user already exists", factor.FriendlyName))
		}
		if factor.IsVerified() {
			numVerifiedFactors += 1
		}
	}

	factorCount := len(factors)
	if err := models.DeleteExpiredFactors(db, config.MFA.FactorExpiryDuration); err != nil {
		return err
	}

	if factorCount >= int(config.MFA.MaxEnrolledFactors) {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && !authSession.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}

	wan, err := webauthn.New(nil)
	if err != nil {
		// TODO!
		return err
	}

	navigatorCreateOptions, session, err := wan.BeginRegistration(user)
	if err != nil {
		return internalServerError("error generating WebAuthn registration data").WithInternalError(err)
	}
	ws := &models.WebAuthnSession{
		SessionData: session,
	}
	factor := models.NewWebAuthnFactor(user, params.FriendlyName)
	challenge := ws.ToChallenge(factor.ID, ipAddress)
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); err != nil {
			return terr
		}
		if terr := tx.Create(challenge); terr != nil {
			return terr
		}
		return nil

	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:           factor.ID,
		ChallengeID:  &challenge.ID,
		FriendlyName: factor.FriendlyName,
		WebAuthn:     navigatorCreateOptions,
	})
}

func (a *API) verifyWebAuthnFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	ctx := r.Context()
	user := getUser(ctx)
	config := a.config
	factor := getFactor(ctx)
	db := a.db.WithContext(ctx)

	challenge, err := factor.FindChallengeByID(db, params.ChallengeID)
	if err != nil {
		return err
	}

	wbn, err := webauthn.New(nil)
	if err != nil {
		return err
	}

	challengeSession := challenge.SessionData.SessionData

	var credential *webauthn.Credential
	if factor.IsUnverified() {
		navigatorCreateResponse, err := params.WebAuthn.CreationResponse.Parse()
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "web_authn.creation_response is not valid").WithInternalError(err)
		}

		credential, err = wbn.CreateCredential(user, challengeSession, navigatorCreateResponse)
		if err != nil {
			// TODO!
			return err
		}
	} else if factor.IsVerified() {
		navigatorGetResponse, err := params.WebAuthn.GetResponse.Parse()
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "web_authn.get_response is not valid").WithInternalError(err)
		}

		credential, err = wbn.ValidateLogin(user, challengeSession, navigatorGetResponse)
		if err != nil {
			// TODO!
			return internalServerError("error validating WebAuthn credentials")
		}
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
			if terr = factor.SaveWebAuthnCredential(tx, credential); terr != nil {
				return terr
			}
		}
		user, terr = models.FindUserByID(tx, user.ID)
		if terr != nil {
			return terr
		}
		token, terr = a.updateMFASessionAndClaims(r, tx, user, models.MFAWebAuthn, models.GrantParams{
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

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	if session == nil || user == nil {
		return internalServerError("A valid session and a registered user are required to enroll a factor")
	}
	params := &EnrollFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	switch params.FactorType {
	case models.WebAuthn:
		if !config.MFA.WebAuthn.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnEnrollDisabled, fmt.Sprintf(ErrorMsgMFAEnrollDisabled, params.FactorType))
		}
		return a.enrollWebAuthnFactor(w, r, params)
	case models.Phone:
		if !config.MFA.Phone.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneEnrollDisabled, fmt.Sprintf(ErrorMsgMFAEnrollDisabled, params.FactorType))
		}
		return a.enrollPhoneFactor(w, r, params)
	case models.TOTP:
		if !config.MFA.TOTP.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, fmt.Sprintf(ErrorMsgMFAEnrollDisabled, params.FactorType))
		}
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be TOTP, Phone, or WebAuthn")
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

	factor = models.NewFactor(user, params.FriendlyName, params.FactorType, models.FactorStateUnverified)
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
	smsProvider, err := sms_provider.GetSmsProvider(*config)
	if err != nil {
		return internalServerError("Failed to get SMS provider").WithInternalError(err)
	}
	if !sms_provider.IsValidMessageChannel(channel, config.Sms.Provider) {
		return badRequestError(ErrorCodeValidationFailed, InvalidChannelError)
	}
	latestValidChallenge, err := factor.FindLatestUnexpiredChallenge(a.db, config.MFA.ChallengeExpiryDuration)
	if err != nil {
		if !models.IsNotFoundError(err) {
			return internalServerError("error finding latest unexpired challenge")
		}
	} else if latestValidChallenge != nil && !latestValidChallenge.SentAt.Add(config.MFA.Phone.MaxFrequency).Before(time.Now()) {
		return tooManyRequestsError(ErrorCodeOverSMSSendRateLimit, generateFrequencyLimitErrorMessage(latestValidChallenge.SentAt, config.MFA.Phone.MaxFrequency))
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

		// We omit messageID for now, can consider reinstating if there are requests.
		_, err := smsProvider.SendMessage(string(factor.Phone), message, channel, otp)
		if err != nil {
			return internalServerError("error sending message").WithInternalError(err)
		}
	}
	if err := db.Transaction(func(tx *storage.Connection) error {
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

func (a *API) challengeWebAuthnFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)
	user := getUser(ctx)
	factor := getFactor(ctx)
	params := &ChallengeFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	ipAddress := utilities.GetIPAddress(r)

	wbn, err := webauthn.New(nil)
	if err != nil {
		return err
	}

	navigatorGetOptions, session, err := wbn.BeginLogin(user)
	if err != nil {
		return err
	}
	ws := &models.WebAuthnSession{
		SessionData: session,
	}
	challenge := ws.ToChallenge(factor.ID, ipAddress)
	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(challenge); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(r, tx, user, models.CreateChallengeAction, r.RemoteAddr, map[string]interface{}{
			"factor_id":     factor.ID,
			"factor_status": factor.Status,
			"factor_type":   factor.FactorType,
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
		WebAuthn:  navigatorGetOptions,
	})
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)
	if factor.IsPhoneFactor() {
		// TODO! Check if verify is enabled
		return a.challengePhoneFactor(w, r)
	}
	if factor.IsWebAuthnFactor() {
		// TODO! Check if verify is enabled
		return a.challengeWebAuthnFactor(w, r)
	}

	totpChallenge := factor.CreateChallenge(ipAddress)

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(totpChallenge); terr != nil {
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
		ID:        totpChallenge.ID,
		ExpiresAt: totpChallenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix(),
	})
}

func (a *API) verifyPhoneFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	ctx := r.Context()
	config := a.config
	user := getUser(ctx)
	factor := getFactor(ctx)
	db := a.db.WithContext(ctx)
	currentIP := utilities.GetIPAddress(r)

	if !factor.IsOwnedBy(user) {
		return notFoundError(ErrorCodeMFAFactorNotFound, "MFA factor not found")

	}

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
	otpCode, shouldReEncrypt, err := challenge.GetOtpCode(config.Security.DBEncryption.DecryptionKeys, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID)
	if err != nil {
		return internalServerError("Database error verifying MFA TOTP secret").WithInternalError(err)
	}
	valid := subtle.ConstantTimeCompare([]byte(otpCode), []byte(params.Code)) == 1
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

func (a *API) VerifyFactor(w http.ResponseWriter, r *http.Request) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	params := &VerifyFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	currentIP := utilities.GetIPAddress(r)

	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
	}

	switch factor.FactorType {
	case models.Phone:
		if !config.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneVerifyDisabled, fmt.Sprintf(ErrorMsgMFAVerifyDisabled, factor.FactorType))
		}
		if params.Code == "" {
			return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
		}
		return a.verifyPhoneFactor(w, r, params)
	case models.TOTP:
		if !config.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, fmt.Sprintf(ErrorMsgMFAVerifyDisabled, factor.FactorType))
		}
		if params.Code == "" {
			return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
		}
	case models.WebAuthn:
		if !config.MFA.WebAuthn.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnEnrollDisabled, fmt.Sprintf(ErrorMsgMFAVerifyDisabled, factor.FactorType))
		}
		return a.verifyWebAuthnFactor(w, r, params)

	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be TOTP, Phone, or WebAuthn")
	}

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
		if shouldReEncrypt && config.Security.DBEncryption.Encrypt && factor.IsTOTPFactor() {
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
	db := a.db.WithContext(ctx)

	if factor == nil || session == nil || user == nil {
		return internalServerError("A valid session and factor are required to unenroll a factor")
	}

	if factor.IsVerified() && !session.IsAAL2() {
		return unprocessableEntityError(ErrorCodeInsufficientAAL, "AAL2 required to unenroll verified factor")
	}
	if !factor.IsOwnedBy(user) {
		return internalServerError(InvalidFactorOwnerErrorMessage)
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
