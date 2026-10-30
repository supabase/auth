package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/ratelimit"
)

// Tests for the email enumeration behavior of PUT /user, see
// supabase/supabase#19071. Each test documents one specific aspect of the
// "address is already registered" handling.
type EmailEnumerationTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
	Mailer *mockclient.MockMailer
}

func TestEmailEnumeration(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)

	ts := &EmailEnumerationTestSuite{
		API:    api,
		Config: config,
		Mailer: mockMailer,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *EmailEnumerationTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// reset every knob the tests below mutate
	ts.Config.Security.HideEmailExists = true
	ts.Config.Mailer.Autoconfirm = false
	ts.Config.Mailer.SecureEmailChangeEnabled = true
	ts.Config.Hook.SendEmail.Enabled = false
	ts.Config.External.AnonymousUsers.Enabled = false
}

func (ts *EmailEnumerationTestSuite) createUser(email string, isAnonymous bool) *models.User {
	u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	u.IsAnonymous = isAnonymous
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving test user")
	return u
}

func (ts *EmailEnumerationTestSuite) generateToken(user *models.User) string {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *EmailEnumerationTestSuite) putUser(token, email string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": email,
	}))
	req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// 1. Hook path leak
// ---------------------------------------------------------------------------

// When the send_email hook is enabled, internal/api/mail.go returns straight
// from the hook invocation and never calls the built-in mailer, so the
// "skip the taken address" logic in internal/mailer/templatemailer never
// runs. This test records what the hook actually receives for a PUT /user
// with an address that is already registered to another account.
func (ts *EmailEnumerationTestSuite) TestSendEmailHookReceivesTakenAddressPayload() {
	// the address that is registered to another account
	other := ts.createUser("hook-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	u := ts.createUser("hook-requester@example.com", false)
	ts.Mailer.Reset()
	token := ts.generateToken(u)

	// hook server capturing the payloads
	var mu sync.Mutex
	var captured []*v0hooks.SendEmailInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := &v0hooks.SendEmailInput{}
		if err := json.NewDecoder(r.Body).Decode(in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		captured = append(captured, in)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v0hooks.SendEmailOutput{})
	}))
	defer srv.Close()

	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Hook.SendEmail.URI = srv.URL
	require.NoError(ts.T(), ts.Config.Hook.SendEmail.PopulateExtensibilityPoint())
	defer func() {
		ts.Config.Hook.SendEmail.Enabled = false
	}()

	w := ts.putUser(token, "hook-taken@example.com")

	// the request itself succeeds (the change is recorded as pending)
	ts.T().Logf("PUT /user with taken address, hook enabled: HTTP status %d", w.Code)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// the hook was called, the built-in mailer was not
	mu.Lock()
	hookCalls := len(captured)
	mu.Unlock()
	ts.T().Logf("hook invocations: %d, built-in mailer EmailChangeMail calls: %d", hookCalls, len(ts.Mailer.EmailChangeMailCalls))
	require.Equal(ts.T(), 1, hookCalls, "send-email hook must have been invoked exactly once")
	require.Empty(ts.T(), ts.Mailer.EmailChangeMailCalls, "built-in mailer must not be called when the hook is enabled")

	payload := captured[0]
	ed := payload.EmailData
	ts.T().Logf("hook email_data: token=%q token_new=%q token_hash=%q token_hash_new=%q email_action_type=%q",
		ed.Token, ed.TokenNew, ed.TokenHash, ed.TokenHashNew, ed.EmailActionType)
	ts.T().Logf("hook user.email=%q user.new_email=%q", payload.User.GetEmail(), payload.User.EmailChange)

	// no token is generated for the taken address: the hook cannot confirm it
	require.Equal(ts.T(), mail.EmailChangeVerification, ed.EmailActionType)
	require.Empty(ts.T(), ed.TokenNew, "no OTP/token must be provided for the taken address")
	require.Empty(ts.T(), ed.TokenHash, "no token hash must be provided for the taken address")

	// dual confirmation is on by default, so the hook does receive a usable
	// token for the user's CURRENT address
	require.NotEmpty(ts.T(), ed.Token, "hook receives the current-address OTP in email_data.token")
	require.NotEmpty(ts.T(), ed.TokenHashNew, "hook receives the current-address token hash in email_data.token_hash_new")

	// the hook must not be handed the taken address: there is no recipient
	// field in the payload, only user.new_email, and the hook would use it
	// to mail the mailbox of the other account
	require.Empty(ts.T(), payload.User.EmailChange,
		"the hook must not be handed the taken address as user.new_email")
	require.Equal(ts.T(), "hook-requester@example.com", payload.User.GetEmail())

	// the built-in mailer never saw this request, so its skip logic did not run
}

// A failing hook must not make the request fail when the address is taken:
// the error would otherwise disclose that the address is registered.
func (ts *EmailEnumerationTestSuite) TestSendEmailHookFailureDoesNotDiscloseTakenAddress() {
	// the address that is registered to another account
	other := ts.createUser("hook-fail-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	u := ts.createUser("hook-fail-requester@example.com", false)
	ts.Mailer.Reset()
	token := ts.generateToken(u)

	// hook server that always fails
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "hook failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Hook.SendEmail.URI = srv.URL
	require.NoError(ts.T(), ts.Config.Hook.SendEmail.PopulateExtensibilityPoint())
	defer func() {
		ts.Config.Hook.SendEmail.Enabled = false
	}()

	// the request succeeds even though the hook failed
	w := ts.putUser(token, "hook-fail-taken@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code,
		"a failing hook must not disclose that the address is taken")

	// and the change is still recorded as pending
	stored, err := models.FindUserByID(ts.API.db, u.ID)
	require.NoError(ts.T(), err, "Error finding test user")
	require.Equal(ts.T(), "hook-fail-taken@example.com", stored.EmailChange)
	require.Empty(ts.T(), stored.EmailChangeTokenNew)
}

// userSpecificResponseFields are the fields of the response that describe
// the user who made the request, the address that was requested, or the
// request itself. The caller knows them, so they cannot disclose whether
// the address is registered.
var userSpecificResponseFields = map[string]bool{
	"id":                   true,
	"email":                true,
	"new_email":            true,
	"created_at":           true,
	"updated_at":           true,
	"email_change_sent_at": true,
	"last_sign_in_at":      true,
	// a random identifier of the request, only present in error responses
	"error_id": true,
}

// A send email hook that fails must not make the response of the request
// depend on whether the new address is already registered.
//
// The hook is given a different payload for a taken address (no pending
// address and no token for it), so a hook that fails on that payload fails
// only the request for the taken address, while a hook that fails outright
// fails only the request for an available address if the error is returned
// for that case only. Either way the status code, and with it the body,
// would disclose whether the address is registered.
func (ts *EmailEnumerationTestSuite) TestSendEmailHookFailureDoesNotDiscloseWhetherAddressIsRegistered() {
	// the address that is registered to another account
	other := ts.createUser("hook-fail-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	// hook server that always fails
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "hook failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Hook.SendEmail.URI = srv.URL
	require.NoError(ts.T(), ts.Config.Hook.SendEmail.PopulateExtensibilityPoint())
	defer func() {
		ts.Config.Hook.SendEmail.Enabled = false
	}()

	// a request for the address that is registered to another account
	takenUser := ts.createUser("hook-fail-taken-requester@example.com", false)
	takenResponse := ts.putUser(ts.generateToken(takenUser), "hook-fail-taken@example.com")

	// a request for an address that is available
	freeUser := ts.createUser("hook-fail-free-requester@example.com", false)
	freeResponse := ts.putUser(ts.generateToken(freeUser), "hook-fail-free@example.com")

	ts.T().Logf("hook failure, registered address: status=%d body=%s", takenResponse.Code, takenResponse.Body.String())
	ts.T().Logf("hook failure, available address: status=%d body=%s", freeResponse.Code, freeResponse.Body.String())

	ts.requireResponsesDoNotDisclose(takenResponse, freeResponse)
}

// A hook that fails only because the payload for a taken address has no
// pending address (and therefore no recipient and no token for it) must not
// disclose the address either: the request for the taken address and the
// request for an available address must have the same status and the same
// body.
func (ts *EmailEnumerationTestSuite) TestSendEmailHookFailureOnMissingRecipientDoesNotDiscloseWhetherAddressIsRegistered() {
	// the address that is registered to another account
	other := ts.createUser("hook-no-recipient-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	// a hook that fails when it is given a user without a pending address,
	// for example because it has no recipient to send the confirmation to
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := &v0hooks.SendEmailInput{}
		if err := json.NewDecoder(r.Body).Decode(in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if in.User.EmailChange == "" {
			http.Error(w, "no recipient for the email change", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v0hooks.SendEmailOutput{})
	}))
	defer srv.Close()

	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Hook.SendEmail.URI = srv.URL
	require.NoError(ts.T(), ts.Config.Hook.SendEmail.PopulateExtensibilityPoint())
	defer func() {
		ts.Config.Hook.SendEmail.Enabled = false
	}()

	// a request for the address that is registered to another account: the
	// hook is given a user without a pending address and fails
	takenUser := ts.createUser("hook-no-recipient-taken-requester@example.com", false)
	takenResponse := ts.putUser(ts.generateToken(takenUser), "hook-no-recipient-taken@example.com")

	// a request for an address that is available: the hook succeeds
	freeUser := ts.createUser("hook-no-recipient-free-requester@example.com", false)
	freeResponse := ts.putUser(ts.generateToken(freeUser), "hook-no-recipient-free@example.com")

	ts.T().Logf("hook failure on missing recipient, registered address: status=%d body=%s", takenResponse.Code, takenResponse.Body.String())
	ts.T().Logf("hook failure on missing recipient, available address: status=%d body=%s", freeResponse.Code, freeResponse.Body.String())

	ts.requireResponsesDoNotDisclose(takenResponse, freeResponse)
}

// POST /resend with type=email_change resends the confirmation of a pending
// email change. It is not authenticated, so a failing hook must not make its
// response depend on whether the pending address is registered either.
func (ts *EmailEnumerationTestSuite) TestSendEmailHookFailureDoesNotDiscloseWhetherAddressIsRegisteredOnResend() {
	// the address that is registered to another account
	other := ts.createUser("hook-fail-resend-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	// hook server that always fails
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "hook failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Hook.SendEmail.URI = srv.URL
	require.NoError(ts.T(), ts.Config.Hook.SendEmail.PopulateExtensibilityPoint())
	defer func() {
		ts.Config.Hook.SendEmail.Enabled = false
	}()

	// two users with a pending email change, one to an address that is
	// registered to another account and one to an address that is available
	takenUser := ts.createUser("hook-fail-resend-taken-requester@example.com", false)
	takenUser.EmailChange = "hook-fail-resend-taken@example.com"
	require.NoError(ts.T(), ts.API.db.Update(takenUser))

	freeUser := ts.createUser("hook-fail-resend-free-requester@example.com", false)
	freeUser.EmailChange = "hook-fail-resend-free@example.com"
	require.NoError(ts.T(), ts.API.db.Update(freeUser))

	takenResponse := ts.resendEmailChange(takenUser.GetEmail())
	freeResponse := ts.resendEmailChange(freeUser.GetEmail())

	ts.T().Logf("hook failure on resend, registered address: status=%d body=%s", takenResponse.Code, takenResponse.Body.String())
	ts.T().Logf("hook failure on resend, available address: status=%d body=%s", freeResponse.Code, freeResponse.Body.String())

	ts.requireResponsesDoNotDisclose(takenResponse, freeResponse)
}

// resendEmailChange asks for the confirmation of a pending email change to
// be sent again.
func (ts *EmailEnumerationTestSuite) resendEmailChange(email string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"type":  mail.EmailChangeVerification,
		"email": email,
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/resend", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

// requireResponsesDoNotDisclose asserts that the response of a request for
// an address that is registered to another account and the response of a
// request for an address that is available cannot be told apart.
func (ts *EmailEnumerationTestSuite) requireResponsesDoNotDisclose(taken, free *httptest.ResponseRecorder) {
	// the status code must not disclose whether the address is registered
	require.Equal(ts.T(), taken.Code, free.Code,
		"the HTTP status must not depend on whether the address is registered")

	// and neither body may disclose it
	for name, response := range map[string]*httptest.ResponseRecorder{
		"registered address": taken,
		"available address":  free,
	} {
		body := response.Body.String()
		require.NotContains(ts.T(), body, string(apierrors.ErrorCodeEmailExists),
			"%s: the response must not report that the address is registered", name)
		require.NotContains(ts.T(), body, DuplicateEmailMsg,
			"%s: the response must not report that the address is registered", name)
		require.NotContains(ts.T(), body, "already registered",
			"%s: the response must not report that the address is registered", name)
	}

	// the two responses must be the same, apart from the fields that
	// describe the user and the address that was requested
	takenBody := map[string]any{}
	require.NoError(ts.T(), json.NewDecoder(taken.Body).Decode(&takenBody))

	freeBody := map[string]any{}
	require.NoError(ts.T(), json.NewDecoder(free.Body).Decode(&freeBody))

	require.ElementsMatch(ts.T(), ts.keysOf(takenBody), ts.keysOf(freeBody),
		"the response must contain the same fields in both cases")

	for key, freeValue := range freeBody {
		if userSpecificResponseFields[key] {
			continue
		}

		require.Equal(ts.T(), freeValue, takenBody[key],
			"the response field %q must not depend on whether the address is registered", key)
	}
}

// keysOf returns the keys of a JSON object.
func (ts *EmailEnumerationTestSuite) keysOf(body map[string]any) []string {
	keys := make([]string, 0, len(body))
	for key := range body {
		keys = append(keys, key)
	}
	return keys
}

// ---------------------------------------------------------------------------
// 2 (see internal/mailer/templatemailer for the mailer unit test)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3. Anonymous user + mailer autoconfirm still discloses the taken address
// ---------------------------------------------------------------------------

// With Mailer.Autoconfirm enabled, an anonymous user converting to a
// permanent account gets a 422 email_exists for an address that is already
// registered, but a 200 for a free address. The status code itself therefore
// still discloses whether an address is registered in that configuration.
func (ts *EmailEnumerationTestSuite) TestAnonymousUserWithAutoconfirmStillDisclosesTakenAddress() {
	ts.Config.Mailer.Autoconfirm = true
	ts.Config.External.AnonymousUsers.Enabled = true
	defer func() {
		ts.Config.Mailer.Autoconfirm = false
		ts.Config.External.AnonymousUsers.Enabled = false
	}()

	other := ts.createUser("anon-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	// anonymous user requesting an address that is already registered
	anonTaken := ts.createUser("", true)
	token := ts.generateToken(anonTaken)

	w := ts.putUser(token, "anon-taken@example.com")
	ts.T().Logf("anonymous user + autoconfirm, PUT /user with taken address: HTTP status %d", w.Code)

	errResponse := apierrors.HTTPError{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResponse))
	ts.T().Logf("error_code=%q msg=%q", errResponse.ErrorCode, errResponse.Message)

	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code,
		"the taken address is disclosed through the 422 email_exists status")
	require.Equal(ts.T(), string(apierrors.ErrorCodeEmailExists), errResponse.ErrorCode)

	// control: a free address succeeds with 200
	anonFree := ts.createUser("", true)
	token = ts.generateToken(anonFree)

	w = ts.putUser(token, "anon-free@example.com")
	ts.T().Logf("anonymous user + autoconfirm, PUT /user with free address: HTTP status %d", w.Code)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := models.User{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	require.Equal(ts.T(), "anon-free@example.com", data.GetEmail())
}

// ---------------------------------------------------------------------------
// 4. Legitimate user dead end
// ---------------------------------------------------------------------------

// A user who requests a change to an address that is registered to another
// account ends up with a pending email_change pointing at that address,
// receives only the confirmation for their current address and can never
// complete the change.
func (ts *EmailEnumerationTestSuite) TestLegitimateUserDeadEndWithTakenAddress() {
	other := ts.createUser("dead-end-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	u := ts.createUser("dead-end-requester@example.com", false)
	ts.Mailer.Reset()
	token := ts.generateToken(u)

	// request the taken address
	w := ts.putUser(token, "dead-end-taken@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// only the current address received a confirmation, no token was created
	// for the taken address
	require.Len(ts.T(), ts.Mailer.EmailChangeMailCalls, 1)
	require.Empty(ts.T(), ts.Mailer.EmailChangeMailCalls[0].OTPNew, "no OTP is sent for the taken address")
	require.NotEmpty(ts.T(), ts.Mailer.EmailChangeMailCalls[0].OTPCurrent, "the current address receives its OTP")
	otpCurrent := ts.Mailer.EmailChangeMailCalls[0].OTPCurrent

	stored, err := models.FindUserByID(ts.API.db, u.ID)
	require.NoError(ts.T(), err, "Error finding test user")
	ts.T().Logf("pending state: email_change=%q email_change_token_new=%q (empty=%v) email_change_token_current set=%v confirm_status=%d",
		stored.EmailChange, stored.EmailChangeTokenNew, stored.EmailChangeTokenNew == "", stored.EmailChangeTokenCurrent != "", stored.EmailChangeConfirmStatus)
	require.Equal(ts.T(), "dead-end-taken@example.com", stored.EmailChange)
	require.Empty(ts.T(), stored.EmailChangeTokenNew, "no token must be created for the taken address")
	require.NotEmpty(ts.T(), stored.EmailChangeTokenCurrent)

	// one_time_tokens: a row exists for the current address only
	_, err = models.FindOneTimeTokenByRelatesTo(ts.API.db, "dead-end-requester@example.com", models.EmailChangeTokenCurrent)
	require.NoError(ts.T(), err, "expected a one_time_token row for the current address")
	_, err = models.FindOneTimeTokenByRelatesTo(ts.API.db, "dead-end-taken@example.com", models.EmailChangeTokenNew)
	require.Error(ts.T(), err, "no one_time_token row must exist for the taken address")
	require.True(ts.T(), models.IsNotFoundError(err))

	// confirming the current address yields the "one of two confirmed"
	// response and does not change the email
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"type":  mail.EmailChangeVerification,
		"token": otpCurrent,
		"email": "dead-end-requester@example.com",
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.T().Logf("verify with current-address OTP: HTTP status %d body=%s", w.Code, w.Body.String())
	require.Equal(ts.T(), http.StatusOK, w.Code)

	resp := map[string]string{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(ts.T(), singleConfirmationAccepted, resp["msg"],
		"the user is told to confirm the other email - which will never arrive")

	// no second confirmation exists: EmailChangeTokenNew is empty, and the
	// current token was consumed, so any confirmation attempt now fails
	stored, err = models.FindUserByID(ts.API.db, u.ID)
	require.NoError(ts.T(), err, "Error finding test user")
	require.Equal(ts.T(), "dead-end-requester@example.com", stored.GetEmail(), "the email must be unchanged")
	require.Empty(ts.T(), stored.EmailChangeTokenNew, "there is no second token that could be confirmed")

	buffer.Reset()
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"type":  mail.EmailChangeVerification,
		"token": otpCurrent,
		"email": "dead-end-requester@example.com",
	}))
	req = httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	body := w.Body.String()
	ts.T().Logf("second verify attempt: HTTP status %d body=%s", w.Code, body)
	require.Equal(ts.T(), http.StatusForbidden, w.Code, "the change can never be completed")

	errResponse := map[string]any{}
	require.NoError(ts.T(), json.NewDecoder(strings.NewReader(body)).Decode(&errResponse))
	require.Equal(ts.T(), string(apierrors.ErrorCodeOTPExpired), errResponse["error_code"])

	// the pending dead-end state is replaced by a subsequent change to a
	// free address (after resetting the per-user send frequency limit)
	buffer.Reset()
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "dead-end-free@example.com",
	}))
	req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.T().Logf("immediate second PUT /user: HTTP status %d (per-user frequency limit)", w.Code)
	require.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	stored.EmailChangeSentAt = nil
	require.NoError(ts.T(), ts.API.db.Update(stored))

	ts.Mailer.Reset()
	w = ts.putUser(token, "dead-end-free@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code)

	stored, err = models.FindUserByID(ts.API.db, u.ID)
	require.NoError(ts.T(), err, "Error finding test user")
	ts.T().Logf("after PUT to free address: email_change=%q email_change_token_new set=%v",
		stored.EmailChange, stored.EmailChangeTokenNew != "")
	require.Equal(ts.T(), "dead-end-free@example.com", stored.EmailChange)
	require.NotEmpty(ts.T(), stored.EmailChangeTokenNew, "a token is created for the free address")
	require.Len(ts.T(), ts.Mailer.EmailChangeMailCalls, 1)
	require.NotEmpty(ts.T(), ts.Mailer.EmailChangeMailCalls[0].OTPNew)
}

// ---------------------------------------------------------------------------
// 5. Rate limit parity
// ---------------------------------------------------------------------------

// countingEmailLimiter wraps a ratelimit.Limiter and records how often
// sending an email was attempted (this is the a.limiterOpts.Email limiter
// consuming config.RateLimitEmailSent).
type countingEmailLimiter struct {
	inner ratelimit.Limiter
	mu    sync.Mutex
	calls int
}

func (l *countingEmailLimiter) Allow() bool {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	return l.inner.Allow()
}

func (l *countingEmailLimiter) AllowAt(at time.Time) bool {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	return l.inner.AllowAt(at)
}

func (l *countingEmailLimiter) Config() conf.Rate {
	return l.inner.Config()
}

func (l *countingEmailLimiter) Calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// The per-user email change frequency limit (config.SMTP.MaxFrequency via
// validateSentWithinFrequencyLimit) and the global email send limiter
// (config.RateLimitEmailSent) must be consumed identically for a taken and a
// free address, so that neither can be used to probe address existence.
func (ts *EmailEnumerationTestSuite) TestEmailChangeRateLimitParityTakenVsFreeAddress() {
	other := ts.createUser("parity-taken@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	userA := ts.createUser("parity-a@example.com", false)
	userB := ts.createUser("parity-b@example.com", false)

	// install the counting limiter
	counter := &countingEmailLimiter{inner: ts.API.limiterOpts.Email}
	prevLimiter := ts.API.limiterOpts.Email
	ts.API.limiterOpts.Email = counter
	defer func() {
		ts.API.limiterOpts.Email = prevLimiter
	}()

	// user A requests the taken address: one global send
	tokenA := ts.generateToken(userA)
	w := ts.putUser(tokenA, "parity-taken@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	ts.T().Logf("PUT taken address: status=%d, global email limiter consumed %d time(s)", w.Code, counter.Calls())
	require.Equal(ts.T(), 1, counter.Calls(), "the taken-address request must consume the global email limiter exactly once")

	// user B requests a free address: one global send
	tokenB := ts.generateToken(userB)
	w = ts.putUser(tokenB, "parity-free@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	ts.T().Logf("PUT free address: status=%d, global email limiter consumed %d time(s)", w.Code, counter.Calls())
	require.Equal(ts.T(), 2, counter.Calls(), "the free-address request must consume the global email limiter exactly once")

	// per-user frequency limit is consumed in both cases: an immediate
	// second request by the same user is rejected before any email send is
	// attempted (the global limiter is not consumed again)
	w = ts.putUser(tokenA, "parity-free@example.com")
	errResponse := apierrors.HTTPError{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResponse))
	ts.T().Logf("second PUT by user A (taken first): status=%d error_code=%s", w.Code, errResponse.ErrorCode)
	require.Equal(ts.T(), http.StatusTooManyRequests, w.Code)
	require.Equal(ts.T(), string(apierrors.ErrorCodeOverEmailSendRateLimit), errResponse.ErrorCode)

	w = ts.putUser(tokenB, "parity-taken@example.com")
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResponse))
	ts.T().Logf("second PUT by user B (free first): status=%d error_code=%s", w.Code, errResponse.ErrorCode)
	require.Equal(ts.T(), http.StatusTooManyRequests, w.Code)
	require.Equal(ts.T(), string(apierrors.ErrorCodeOverEmailSendRateLimit), errResponse.ErrorCode)

	ts.T().Logf("global email limiter consumed %d time(s) after four requests (expected 2)", counter.Calls())
	require.Equal(ts.T(), 2, counter.Calls(),
		"rate limited requests must not consume the global email limiter")
}

// ---------------------------------------------------------------------------
// 6. Confirm-time re-check (the "no disclosure" message assertion for the
// existing TestUserUpdateEmailConfirmationToRegisteredAddress lives in
// user_test.go; this test verifies the flow end to end with the message
// assertion included).
// ---------------------------------------------------------------------------

// When an address is registered by another account between the request and
// the confirmation, the confirmation fails with 403 otp_expired and the
// error message must not disclose that the address is registered. With dual
// confirmation enabled (the default), the first verify returns the neutral
// "one of two confirmed" response and the re-check happens on the final
// confirmation.
func (ts *EmailEnumerationTestSuite) TestEmailChangeConfirmTimeReCheckDoesNotDiscloseRegistration() {
	u := ts.createUser("recheck-requester@example.com", false)
	ts.Mailer.Reset()
	token := ts.generateToken(u)

	// the address is free when the change is requested
	w := ts.putUser(token, "recheck@example.com")
	require.Equal(ts.T(), http.StatusOK, w.Code)

	require.Len(ts.T(), ts.Mailer.EmailChangeMailCalls, 1)
	otpNew := ts.Mailer.EmailChangeMailCalls[0].OTPNew
	otpCurrent := ts.Mailer.EmailChangeMailCalls[0].OTPCurrent
	require.NotEmpty(ts.T(), otpNew)
	require.NotEmpty(ts.T(), otpCurrent)

	// another account registers the address in the meantime
	other := ts.createUser("recheck@example.com", false)
	require.NoError(ts.T(), other.Confirm(ts.API.db), "Error confirming test user")

	verify := func(otp, email string) *httptest.ResponseRecorder {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"type":  mail.EmailChangeVerification,
			"token": otp,
			"email": email,
		}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		return w
	}

	// first confirmation step: neutral "one of two confirmed" response,
	// nothing discloses that the address was registered in the meantime
	w = verify(otpNew, "recheck@example.com")
	ts.T().Logf("first verify step: HTTP status %d body=%s", w.Code, w.Body.String())
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Contains(ts.T(), w.Body.String(), singleConfirmationAccepted)
	require.NotContains(ts.T(), w.Body.String(), "already registered")

	// final confirmation step: the address is re-checked and reported as
	// invalid, without disclosing that it is registered
	w = verify(otpCurrent, "recheck-requester@example.com")
	body := w.Body.String()
	ts.T().Logf("final verify step: HTTP status %d body=%s", w.Code, body)

	require.Equal(ts.T(), http.StatusForbidden, w.Code)
	require.Contains(ts.T(), body, string(apierrors.ErrorCodeOTPExpired))
	require.NotContains(ts.T(), body, "already registered",
		"the error must not disclose that the address is registered")
	require.NotContains(ts.T(), body, DuplicateEmailMsg)

	stored, err := models.FindUserByID(ts.API.db, u.ID)
	require.NoError(ts.T(), err, "Error finding test user")
	require.Equal(ts.T(), "recheck-requester@example.com", stored.GetEmail(), "the email must be unchanged")
}
