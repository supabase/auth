package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	"github.com/supabase/auth/internal/conf"
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
	ID           uuid.UUID   `json:"id"`
	Type         string      `json:"type"`
	FriendlyName string      `json:"friendly_name"`
	TOTP         *TOTPObject `json:"totp,omitempty"`
	Phone        string      `json:"phone,omitempty"`
}

type ChallengeFactorParams struct {
	Channel  string          `json:"channel"`
	WebAuthn *WebAuthnParams `json:"web_authn,omitempty"`
}

type VerifyFactorParams struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	Code        string          `json:"code"`
	WebAuthn    *WebAuthnParams `json:"web_authn,omitempty"`
}

type ChallengeFactorResponse struct {
	ID                        uuid.UUID                        `json:"id"`
	Type                      string                           `json:"type"`
	ExpiresAt                 int64                            `json:"expires_at,omitempty"`
	CredentialRequestOptions  *wbnprotocol.CredentialAssertion `json:"credential_request_options,omitempty"`
	CredentialCreationOptions *wbnprotocol.CredentialCreation  `json:"credential_creation_options,omitempty"`
}

type UnenrollFactorResponse struct {
	ID uuid.UUID `json:"id"`
}

type WebAuthnParams struct {
	RPID string `json:"rp_id,omitempty"`
	// Can encode multiple origins as comma separated values like: "origin1,origin2"
	RPOrigins         string          `json:"rp_origins,omitempty"`
	AssertionResponse json.RawMessage `json:"assertion_response,omitempty"`
	CreationResponse  json.RawMessage `json:"creation_response,omitempty"`
}

func (w *WebAuthnParams) GetRPOrigins() []string {
	if w.RPOrigins == "" {
		return nil
	}
	return strings.Split(w.RPOrigins, ",")
}

func (w *WebAuthnParams) ToConfig() (*webauthn.WebAuthn, error) {
	if w.RPID == "" {
		return nil, fmt.Errorf("webAuthn RP ID cannot be empty")
	}

	origins := w.GetRPOrigins()
	if len(origins) == 0 {
		return nil, fmt.Errorf("webAuthn RP Origins cannot be empty")
	}

	var validOrigins []string
	var invalidOrigins []string

	for _, origin := range origins {
		parsedURL, err := url.Parse(origin)
		if err != nil || (parsedURL.Scheme != "https" && !(parsedURL.Scheme == "http" && parsedURL.Hostname() == "localhost")) || parsedURL.Host == "" {
			invalidOrigins = append(invalidOrigins, origin)
		} else {
			validOrigins = append(validOrigins, origin)
		}
	}

	if len(invalidOrigins) > 0 {
		return nil, fmt.Errorf("invalid RP origins: %s", strings.Join(invalidOrigins, ", "))
	}

	wconfig := &webauthn.Config{
		// DisplayName is optional in spec but required to be non-empty in libary, we use the RPID as a placeholder.
		RPDisplayName: w.RPID,
		RPID:          w.RPID,
		RPOrigins:     validOrigins,
	}

	return webauthn.New(wconfig)
}

const (
	QRCodeGenerationErrorMessage = "Error generating QR Code"
)

func validateFactors(db *storage.Connection, user *models.User, newFactorName string, config *conf.GlobalConfiguration, session *models.Session) error {
	if err := models.DeleteExpiredFactors(db, config.MFA.FactorExpiryDuration); err != nil {
		return err
	}
	if err := db.Load(user, "Factors"); err != nil {
		return err
	}
	factorCount := len(user.Factors)
	numVerifiedFactors := 0

	for _, factor := range user.Factors {
		if factor.FriendlyName == newFactorName {
			return unprocessableEntityError(
				ErrorCodeMFAFactorNameConflict,
				fmt.Sprintf("A factor with the friendly name %q for this user already exists", newFactorName),
			)
		}
		if factor.IsVerified() {
			numVerifiedFactors++
		}
	}

	if factorCount >= int(config.MFA.MaxEnrolledFactors) {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors >= config.MFA.MaxVerifiedFactors {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors, "Maximum number of verified factors reached, unenroll to continue")
	}

	if numVerifiedFactors > 0 && session != nil && !session.IsAAL2() {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
	}

	return nil
}

func (a *API) enrollPhoneFactor(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	ctx := r.Context()
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

	var factorsToDelete []models.Factor
	for _, factor := range user.Factors {
		if factor.IsPhoneFactor() && factor.Phone.String() == phone {
			if factor.IsVerified() {
				return unprocessableEntityError(
					ErrorCodeMFAVerifiedFactorExists,
					"A verified phone factor already exists, unenroll the existing factor to continue",
				)
			} else if factor.IsUnverified() {
				factorsToDelete = append(factorsToDelete, factor)
			}
		}
	}

	if err := db.Destroy(&factorsToDelete); err != nil {
		return internalServerError("Database error deleting unverified phone factors").WithInternalError(err)
	}

	if err := validateFactors(db, user, params.FriendlyName, a.config, session); err != nil {
		return err
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

func (a *API) enrollWebAuthnFactor(w http.ResponseWriter, r *http.Request, params *EnrollFactorParams) error {
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	db := a.db.WithContext(ctx)

	if err := validateFactors(db, user, params.FriendlyName, a.config, session); err != nil {
		return err
	}

	factor := models.NewWebAuthnFactor(user, params.FriendlyName)
	err := db.Transaction(func(tx *storage.Connection) error {
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
		Type:         models.WebAuthn,
		FriendlyName: factor.FriendlyName,
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

	if err := validateFactors(db, user, params.FriendlyName, config, session); err != nil {
		return err
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
		TOTP: &TOTPObject{
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
	case models.WebAuthn:
		if !config.MFA.WebAuthn.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnEnrollDisabled, "MFA enroll is disabled for WebAuthn")
		}
		return a.enrollWebAuthnFactor(w, r, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
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

func (a *API) challengeWebAuthnFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	user := getUser(ctx)
	factor := getFactor(ctx)
	ipAddress := utilities.GetIPAddress(r)

	params := &ChallengeFactorParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.WebAuthn == nil {
		return badRequestError(ErrorCodeValidationFailed, "web_authn config required")
	}
	webAuthn, err := params.WebAuthn.ToConfig()
	if err != nil {
		return err
	}
	var response *ChallengeFactorResponse
	var ws *models.WebAuthnSessionData
	var challenge *models.Challenge
	if factor.IsUnverified() {
		options, session, err := webAuthn.BeginRegistration(user)
		if err != nil {
			return internalServerError("Failed to generate WebAuthn registration data").WithInternalError(err)
		}
		ws = &models.WebAuthnSessionData{
			SessionData: session,
		}
		challenge = ws.ToChallenge(factor.ID, ipAddress)

		response = &ChallengeFactorResponse{
			CredentialCreationOptions: options,
			Type:                      factor.FactorType,
			ID:                        challenge.ID,
		}

	} else if factor.IsVerified() {
		options, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			return err
		}
		ws = &models.WebAuthnSessionData{
			SessionData: session,
		}
		challenge = ws.ToChallenge(factor.ID, ipAddress)
		response = &ChallengeFactorResponse{
			CredentialRequestOptions: options,
			Type:                     factor.FactorType,
			ID:                       challenge.ID,
		}

	}

	if err := factor.WriteChallengeToDatabase(db, challenge); err != nil {
		return err
	}
	response.ExpiresAt = challenge.GetExpiryTime(config.MFA.ChallengeExpiryDuration).Unix()

	return sendJSON(w, http.StatusOK, response)

}

func (a *API) validateChallenge(r *http.Request, db *storage.Connection, factor *models.Factor, challengeID uuid.UUID) (*models.Challenge, error) {
	config := a.config
	currentIP := utilities.GetIPAddress(r)

	challenge, err := factor.FindChallengeByID(db, challengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, unprocessableEntityError(ErrorCodeMFAFactorNotFound, "MFA factor with the provided challenge ID not found")
		}
		return nil, internalServerError("Database error finding Challenge").WithInternalError(err)
	}

	if challenge.VerifiedAt != nil || challenge.IPAddress != currentIP {
		return nil, unprocessableEntityError(ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch.")
	}

	if challenge.HasExpired(config.MFA.ChallengeExpiryDuration) {
		if err := db.Destroy(challenge); err != nil {
			return nil, internalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return nil, unprocessableEntityError(ErrorCodeMFAChallengeExpired, "MFA challenge %v has expired, verify against another challenge or create a new challenge.", challenge.ID)
	}

	return challenge, nil
}

func (a *API) ChallengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	factor := getFactor(ctx)

	switch factor.FactorType {
	case models.Phone:
		if !config.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneVerifyDisabled, "MFA verification is disabled for Phone")
		}
		return a.challengePhoneFactor(w, r)

	case models.TOTP:
		if !config.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPVerifyDisabled, "MFA verification is disabled for TOTP")
		}
		return a.challengeTOTPFactor(w, r)
	case models.WebAuthn:
		if !config.MFA.WebAuthn.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnVerifyDisabled, "MFA verification is disabled for WebAuthn")
		}
		return a.challengeWebAuthnFactor(w, r)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
	}

}

func (a *API) verifyTOTPFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	var err error
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	config := a.config
	db := a.db.WithContext(ctx)

	challenge, err := a.validateChallenge(r, db, factor, params.ChallengeID)
	if err != nil {
		return err
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

	challenge, err := a.validateChallenge(r, db, factor, params.ChallengeID)
	if err != nil {
		return err
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
	if config.Sms.IsTwilioVerifyProvider() {
		smsProvider, err := sms_provider.GetSmsProvider(*config)
		if err != nil {
			return internalServerError("Failed to get SMS provider").WithInternalError(err)
		}
		if err := smsProvider.VerifyOTP(factor.Phone.String(), params.Code); err != nil {
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

func (a *API) verifyWebAuthnFactor(w http.ResponseWriter, r *http.Request, params *VerifyFactorParams) error {
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)
	db := a.db.WithContext(ctx)

	var webAuthn *webauthn.WebAuthn
	var credential *webauthn.Credential
	var err error

	switch {
	case params.WebAuthn == nil:
		return badRequestError(ErrorCodeValidationFailed, "WebAuthn config required")
	case factor.IsVerified() && params.WebAuthn.AssertionResponse == nil:
		return badRequestError(ErrorCodeValidationFailed, "creation_response required to login")
	case factor.IsUnverified() && params.WebAuthn.CreationResponse == nil:
		return badRequestError(ErrorCodeValidationFailed, "assertion_response required to login")
	default:
		webAuthn, err = params.WebAuthn.ToConfig()
		if err != nil {
			return err
		}
	}

	challenge, err := a.validateChallenge(r, db, factor, params.ChallengeID)
	if err != nil {
		return err
	}
	webAuthnSession := *challenge.WebAuthnSessionData.SessionData
	// Once the challenge is validated, we consume the challenge
	if err := db.Destroy(challenge); err != nil {
		return internalServerError("Database error deleting challenge").WithInternalError(err)
	}

	if factor.IsUnverified() {
		parsedResponse, err := wbnprotocol.ParseCredentialCreationResponseBody(bytes.NewReader(params.WebAuthn.CreationResponse))
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "Invalid credential_creation_response")
		}
		credential, err = webAuthn.CreateCredential(user, webAuthnSession, parsedResponse)
		if err != nil {
			return err
		}

	} else if factor.IsVerified() {
		parsedResponse, err := wbnprotocol.ParseCredentialRequestResponseBody(bytes.NewReader(params.WebAuthn.AssertionResponse))
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "Invalid credential_request_response")
		}
		credential, err = webAuthn.ValidateLogin(user, webAuthnSession, parsedResponse)
		if err != nil {
			return internalServerError("Failed to validate WebAuthn MFA response").WithInternalError(err)
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
		// Challenge verification not needed as the challenge is destroyed on use
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
		if terr = models.InvalidateSessionsWithAALLessThan(tx, user.ID, models.AAL2.String()); terr != nil {
			return internalServerError("Failed to update session").WithInternalError(terr)
		}
		if terr = models.DeleteUnverifiedFactors(tx, user, models.WebAuthn); terr != nil {
			return internalServerError("Failed to remove unverified MFA WebAuthn factors").WithInternalError(terr)
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
	if params.Code == "" && factor.FactorType != models.WebAuthn {
		return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
	}

	switch factor.FactorType {
	case models.Phone:
		if !config.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneVerifyDisabled, "MFA verification is disabled for Phone")
		}

		return a.verifyPhoneFactor(w, r, params)
	case models.TOTP:
		if !config.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPVerifyDisabled, "MFA verification is disabled for TOTP")
		}
		return a.verifyTOTPFactor(w, r, params)
	case models.WebAuthn:
		if !config.MFA.WebAuthn.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnEnrollDisabled, "MFA verification is disabled for WebAuthn")
		}
		return a.verifyWebAuthnFactor(w, r, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
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
