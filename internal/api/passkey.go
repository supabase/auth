package api

import (
	"bytes"
	"net/http"
	"time"

	wbnprotocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/tokens"
	"github.com/supabase/auth/internal/utilities"
)

type PasskeyRegistrationRequest struct {
	FriendlyName string          `json:"friendly_name"`
	WebAuthn     *WebAuthnParams `json:"webauthn"`
}

type PasskeyRegistrationResponse struct {
	PasskeyID    uuid.UUID              `json:"passkey_id"`
	ChallengeID  uuid.UUID              `json:"challenge_id"`
	FriendlyName string                 `json:"friendly_name,omitempty"`
	ExpiresAt    int64                  `json:"expires_at,omitempty"`
	WebAuthn     *WebAuthnChallengeData `json:"webauthn,omitempty"`
}

type PasskeyVerifyRequest struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	WebAuthn    *WebAuthnParams `json:"webauthn"`
}

type PasskeySummary struct {
	ID           uuid.UUID  `json:"id"`
	FriendlyName string     `json:"friendly_name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

type PasskeySignInRequest struct {
	WebAuthn *WebAuthnParams `json:"webauthn"`
}

type PasskeySignInResponse struct {
	ChallengeID uuid.UUID              `json:"challenge_id"`
	ExpiresAt   int64                  `json:"expires_at,omitempty"`
	WebAuthn    *WebAuthnChallengeData `json:"webauthn,omitempty"`
}

type PasskeySignInVerifyRequest struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	WebAuthn    *WebAuthnParams `json:"webauthn"`
}

type passkeyWebAuthnUser struct {
	user        *models.User
	credentials []webauthn.Credential
}

func (p passkeyWebAuthnUser) WebAuthnID() []byte {
	return p.user.WebAuthnID()
}

func (p passkeyWebAuthnUser) WebAuthnName() string {
	return p.user.WebAuthnName()
}

func (p passkeyWebAuthnUser) WebAuthnDisplayName() string {
	return p.user.WebAuthnDisplayName()
}

func (p passkeyWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return p.credentials
}

func (a *API) ensurePasskeysEnabled() error {
	if !a.config.Passkey.Enabled {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Passkeys are disabled")
	}
	return nil
}

func (a *API) listPasskeys(w http.ResponseWriter, r *http.Request, user *models.User) error {
	summaries := []PasskeySummary{}
	for _, factor := range user.Factors {
		if !factor.IsPasskeyFactor() {
			continue
		}
		summaries = append(summaries, PasskeySummary{
			ID:           factor.ID,
			FriendlyName: factor.FriendlyName,
			CreatedAt:    factor.CreatedAt,
			UpdatedAt:    factor.UpdatedAt,
			LastUsedAt:   factor.LastChallengedAt,
		})
	}
	return sendJSON(w, http.StatusOK, map[string]interface{}{"passkeys": summaries})
}

func (a *API) ListPasskeys(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	user := getUser(r.Context())
	if user == nil {
		return apierrors.NewInternalServerError("No user in context")
	}
	if err := a.db.WithContext(r.Context()).Load(user, "Factors"); err != nil {
		return apierrors.NewInternalServerError("Database error loading factors").WithInternalError(err)
	}
	return a.listPasskeys(w, r, user)
}

func (a *API) CreatePasskey(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	if user == nil || session == nil {
		return apierrors.NewInternalServerError("A valid session and user are required to register passkeys")
	}

	params := &PasskeyRegistrationRequest{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.WebAuthn == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "web_authn config required")
	}
	webAuthn, err := params.WebAuthn.ToConfig()
	if err != nil {
		return err
	}
	if params.FriendlyName == "" {
		params.FriendlyName = "Passkey"
	}

	db := a.db.WithContext(ctx)
	if err := db.Load(user, "Factors"); err != nil {
		return apierrors.NewInternalServerError("Database error loading user factors").WithInternalError(err)
	}

	if err := models.DeleteUnverifiedPasskeyFactors(db, user); err != nil {
		return apierrors.NewInternalServerError("Database error cleaning up passkeys").WithInternalError(err)
	}

	factor := models.NewPasskeyFactor(user, params.FriendlyName)
	ipAddress := utilities.GetIPAddress(r)

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.EnrollFactorAction, ipAddress, map[string]interface{}{
			"factor_id":   factor.ID,
			"factor_type": factor.FactorType,
			"is_passkey":  true,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Reload user factors to include the new passkey for exclusion list
	if err := db.Load(user, "Factors"); err != nil {
		return apierrors.NewInternalServerError("Database error loading user factors").WithInternalError(err)
	}

	excludeList := []wbnprotocol.CredentialDescriptor{}
	for _, cred := range user.PasskeyCredentials() {
		excludeList = append(excludeList, wbnprotocol.CredentialDescriptor{
			Type:         wbnprotocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    []wbnprotocol.AuthenticatorTransport{"usb", "nfc", "ble", "internal"},
		})
	}

	options, sessionData, err := webAuthn.BeginRegistration(user, webauthn.WithExclusions(excludeList))
	if err != nil {
		return apierrors.NewInternalServerError("Failed to generate WebAuthn registration data").WithInternalError(err)
	}

	challenge := (&models.WebAuthnSessionData{SessionData: sessionData}).ToChallenge(factor.ID, ipAddress)
	if err := factor.WriteChallengeToDatabase(db, challenge); err != nil {
		return err
	}

	response := &PasskeyRegistrationResponse{
		PasskeyID:    factor.ID,
		ChallengeID:  challenge.ID,
		FriendlyName: factor.FriendlyName,
		ExpiresAt:    challenge.GetExpiryTime(a.config.Passkey.ChallengeExpiryDuration).Unix(),
		WebAuthn: &WebAuthnChallengeData{
			Type:              "create",
			CredentialOptions: options,
		},
	}
	return sendJSON(w, http.StatusOK, response)
}

func (a *API) VerifyPasskey(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	ctx := r.Context()
	user := getUser(ctx)
	if user == nil {
		return apierrors.NewInternalServerError("No user in context")
	}
	factor := getFactor(ctx)
	if factor == nil || !factor.IsPasskeyFactor() {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeMFAFactorNotFound, "Passkey not found")
	}

	params := &PasskeyVerifyRequest{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.WebAuthn == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "WebAuthn config required")
	}
	if params.WebAuthn.Type != "create" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "WebAuthn type must be create")
	}
	if params.WebAuthn.CredentialResponse == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "credential_response required")
	}

	webAuthn, err := params.WebAuthn.ToConfig()
	if err != nil {
		return err
	}

	db := a.db.WithContext(ctx)
	challenge, err := a.validateChallenge(r, db, factor, params.ChallengeID)
	if err != nil {
		return err
	}

	parsedResponse, err := wbnprotocol.ParseCredentialCreationResponseBody(bytes.NewReader(params.WebAuthn.CredentialResponse))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid credential_response")
	}

	credential, err := webAuthn.CreateCredential(user, *challenge.WebAuthnSessionData.SessionData, parsedResponse)
	if err != nil {
		return err
	}

	if err := db.Destroy(challenge); err != nil {
		return apierrors.NewInternalServerError("Database error deleting challenge").WithInternalError(err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if !factor.IsVerified() {
			if terr := factor.UpdateStatus(tx, models.FactorStateVerified); terr != nil {
				return terr
			}
		}
		if terr := factor.SaveWebAuthnCredential(tx, credential); terr != nil {
			return terr
		}
		if terr := factor.UpdateLastWebAuthnChallenge(tx, challenge, params.WebAuthn.Type, parsedResponse); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.VerifyFactorAction, utilities.GetIPAddress(r), map[string]interface{}{
			"factor_id":   factor.ID,
			"factor_type": factor.FactorType,
			"is_passkey":  true,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{"passkey_id": factor.ID})
}

func (a *API) DeletePasskey(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	ctx := r.Context()
	user := getUser(ctx)
	session := getSession(ctx)
	factor := getFactor(ctx)
	if user == nil || session == nil || factor == nil {
		return apierrors.NewInternalServerError("A valid session and passkey are required to delete a passkey")
	}
	if !factor.IsPasskeyFactor() {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeMFAFactorNotFound, "Passkey not found")
	}
	if factor.IsVerified() && !session.IsAAL2() {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeInsufficientAAL, "AAL2 required to delete verified passkey")
	}
	db := a.db.WithContext(ctx)
	err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Destroy(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.DeleteFactorAction, utilities.GetIPAddress(r), map[string]interface{}{
			"factor_id":   factor.ID,
			"factor_type": factor.FactorType,
			"is_passkey":  true,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, map[string]interface{}{"passkey_id": factor.ID})
}

func (a *API) PasskeySignIn(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	params := &PasskeySignInRequest{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.WebAuthn == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "web_authn config required")
	}
	if params.WebAuthn.Type != "request" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "WebAuthn type must be request")
	}
	webAuthn, err := params.WebAuthn.ToConfig()
	if err != nil {
		return err
	}

	options, sessionData, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return apierrors.NewInternalServerError("Failed to generate WebAuthn passkey challenge").WithInternalError(err)
	}

	db := a.db.WithContext(r.Context())
	ipAddress := utilities.GetIPAddress(r)
	challenge := models.NewPasskeyChallenge(sessionData, nil, ipAddress)
	if err := db.Create(challenge); err != nil {
		return apierrors.NewInternalServerError("Database error creating challenge").WithInternalError(err)
	}

	expiresAt := time.Now().Add(time.Second * time.Duration(a.config.Passkey.ChallengeExpiryDuration))

	response := &PasskeySignInResponse{
		ChallengeID: challenge.ID,
		ExpiresAt:   expiresAt.Unix(),
		WebAuthn: &WebAuthnChallengeData{
			Type:              "request",
			CredentialOptions: options,
		},
	}
	return sendJSON(w, http.StatusOK, response)
}

func (a *API) PasskeySignInVerify(w http.ResponseWriter, r *http.Request) error {
	if err := a.ensurePasskeysEnabled(); err != nil {
		return err
	}
	params := &PasskeySignInVerifyRequest{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}
	if params.WebAuthn == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "web_authn config required")
	}
	if params.WebAuthn.Type != "request" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "WebAuthn type must be request")
	}
	if params.WebAuthn.CredentialResponse == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "credential_response required")
	}
	webAuthn, err := params.WebAuthn.ToConfig()
	if err != nil {
		return err
	}

	db := a.db.WithContext(r.Context())
	challenge, err := models.FindPasskeyChallengeByID(db, params.ChallengeID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAFactorNotFound, "Challenge not found")
		}
		return apierrors.NewInternalServerError("Database error finding challenge").WithInternalError(err)
	}
	if challenge.WebAuthnSessionData == nil || challenge.WebAuthnSessionData.SessionData == nil {
		return apierrors.NewInternalServerError("Challenge missing session data")
	}
	if challenge.HasExpired(time.Duration(a.config.Passkey.ChallengeExpiryDuration) * time.Second) {
		if err := db.Destroy(challenge); err != nil {
			return apierrors.NewInternalServerError("Database error deleting challenge").WithInternalError(err)
		}
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAChallengeExpired, "Passkey challenge has expired")
	}
	if challenge.IPAddress != utilities.GetIPAddress(r) {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAIPAddressMismatch, "Challenge and verify IP addresses mismatch.")
	}

	parsedResponse, err := wbnprotocol.ParseCredentialRequestResponseBody(bytes.NewReader(params.WebAuthn.CredentialResponse))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid credential_response")
	}

	assertion := parsedResponse
	if assertion.Response.UserHandle == nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "User handle missing from credential_response")
	}

	userID, err := uuid.FromString(string(assertion.Response.UserHandle))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid user handle in credential_response")
	}

	baseUser, err := models.FindUserByID(db, userID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeUserNotFound, "User not found for passkey")
		}
		return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
	}
	if err := db.Load(baseUser, "Factors"); err != nil {
		return apierrors.NewInternalServerError("Database error loading passkeys").WithInternalError(err)
	}

	credentials := baseUser.PasskeyCredentials()
	if len(credentials) == 0 {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAFactorNotFound, "No passkeys registered")
	}

	passkeyUser := passkeyWebAuthnUser{user: baseUser, credentials: credentials}
	sessionData := *challenge.WebAuthnSessionData.SessionData
	sessionData.UserID = passkeyUser.WebAuthnID()

	credential, err := webAuthn.ValidateLogin(passkeyUser, sessionData, assertion)
	if err != nil {
		return apierrors.NewInternalServerError("Failed to validate passkey response").WithInternalError(err)
	}
	if baseUser.IsBanned() {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeUserBanned, "User is banned")
	}

	factor, err := models.FindPasskeyFactorByCredentialID(db, baseUser.ID, credential.ID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeMFAFactorNotFound, "Passkey not found for user")
		}
		return apierrors.NewInternalServerError("Database error finding passkey").WithInternalError(err)
	}

	if err := db.Destroy(challenge); err != nil {
		return apierrors.NewInternalServerError("Database error deleting challenge").WithInternalError(err)
	}

	grantParams := models.GrantParams{}
	grantParams.FillGrantParams(r)
	grantParams.FactorID = &factor.ID

	var token *tokens.AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, baseUser, models.LoginAction, utilities.GetIPAddress(r), map[string]interface{}{
			"provider": PasskeyProvider,
		}); terr != nil {
			return terr
		}
		var terr error
		token, terr = a.issueRefreshToken(r, tx, baseUser, models.Passkey, grantParams)
		if terr != nil {
			return terr
		}
		now := time.Now()
		factor.LastChallengedAt = &now
		if terr = tx.UpdateOnly(factor, "last_challenged_at", "updated_at"); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	metering.RecordLogin(metering.LoginTypePasskey, baseUser.ID, &metering.LoginData{Provider: PasskeyProvider})

	return sendJSON(w, http.StatusOK, token)
}
