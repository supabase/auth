package api

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func ssoProviderType(providerID uuid.UUID) string {
	return "sso:" + providerID.String()
}

func (ts *SCIMTestSuite) newUser(email string, sso bool) *models.User {
	user, err := models.NewUser("", email, "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	user.IsSSOUser = sso
	require.NoError(ts.T(), ts.API.db.Create(user))
	return user
}

func (ts *SCIMTestSuite) addIdentity(user *models.User, kind string, data map[string]any) {
	identity, err := models.NewIdentity(user, kind, data)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
}

func (ts *SCIMTestSuite) ssoUser(p *models.SSOProvider, sub, email string) *models.User {
	user := ts.newUser(email, true)
	ts.addIdentity(user, ssoProviderType(p.ID), map[string]any{"sub": sub, "email": email})
	return user
}

func (ts *SCIMTestSuite) scimRow(id string) models.SCIMUser {
	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	return row
}

func (ts *SCIMTestSuite) linkedUser(id string) *models.User {
	row := ts.scimRow(id)
	require.NotNil(ts.T(), row.UserID)
	return ts.reloadUser(*row.UserID)
}

func (ts *SCIMTestSuite) identities(user *models.User) []*models.Identity {
	identities, err := models.FindIdentitiesByUserID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	return identities
}

func (ts *SCIMTestSuite) ssoIdentity(sub string) *models.Identity {
	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, sub, ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
	return identity
}

func (ts *SCIMTestSuite) expect(status int, method, path, body string) map[string]any {
	w, got := ts.do(ts.TokenA, method, path, body)
	require.Equal(ts.T(), status, w.Code, w.Body.String())
	return got
}

func (ts *SCIMTestSuite) TestCreateProvisionsSSOUser() {
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.Equal(ts.T(), ts.API.config.JWT.Aud, user.Aud)
	require.NotNil(ts.T(), user.EmailConfirmedAt)
	require.False(ts.T(), user.IsBanned())
	require.Equal(ts.T(), []any{ssoProviderType(ts.A.ID)}, user.AppMetaData["providers"])

	identities := ts.identities(user)
	require.Len(ts.T(), identities, 1)
	require.Equal(ts.T(), ssoProviderType(ts.A.ID), identities[0].Provider)
	require.Equal(ts.T(), "Alice@Example.com", identities[0].ProviderID)
}

func (ts *SCIMTestSuite) TestCreateDoesNotLinkOutsideProvider() {
	password := ts.newUser("alice@example.com", false)
	other := ts.ssoUser(ts.B, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.NotEqual(ts.T(), other.ID, user.ID)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, ts.passkeyRegistrationOptions(user))
	reloaded := ts.reloadUser(password.ID)
	require.False(ts.T(), reloaded.IsSSOUser)
	require.Empty(ts.T(), ts.identities(reloaded))
	require.Len(ts.T(), ts.identities(other), 1)
}

func (ts *SCIMTestSuite) TestCreateReusesSAMLIdentity() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) passkeyRegistrationOptions(user *models.User) int {
	passkey, webauthn := ts.API.config.Passkey, ts.API.config.WebAuthn
	defer func() { ts.API.config.Passkey, ts.API.config.WebAuthn = passkey, webauthn }()
	ts.API.config.Passkey.Enabled = true
	ts.API.config.WebAuthn = conf.WebAuthnConfiguration{
		RPID:                    "localhost",
		RPDisplayName:           "Test App",
		RPOrigins:               []string{"http://localhost:3000"},
		ChallengeExpiryDuration: 5 * time.Minute,
	}

	r := httptest.NewRequest(http.MethodPost, "/passkeys/registration/options", nil)
	r.Header.Set("Authorization", "Bearer "+ts.accessToken(user))
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w.Code
}

func (ts *SCIMTestSuite) TestNonSSOUserWithSSOIdentityEmailIsNeverLinked() {
	ts.requireNonSSOUserNeverLinked("saml-name-id")
}

func (ts *SCIMTestSuite) TestNonSSOUserWithSSOIdentitySubjectIsNeverLinked() {
	ts.requireNonSSOUserNeverLinked("Alice@Example.com")
}

func (ts *SCIMTestSuite) requireNonSSOUserNeverLinked(sub string) {
	password := ts.newUser("alice@example.com", false)
	ts.addIdentity(password, ssoProviderType(ts.A.ID), map[string]any{"sub": sub, "email": "alice@example.com", "email_verified": true})

	require.Equal(ts.T(), "uniqueness", ts.expect(http.StatusConflict, http.MethodPost, "/Users", oktaUser)["scimType"])
	reloaded := ts.reloadUser(password.ID)
	require.False(ts.T(), reloaded.IsSSOUser)
	require.Len(ts.T(), ts.identities(reloaded), 1)
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "user_id = ?", password.ID))
}

func (ts *SCIMTestSuite) TestLinkAccountKeepsUserSSO() {
	password := ts.newUser("alice@example.com", false)
	existing := ts.ssoUser(ts.A, "saml-name-id", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 2)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, ts.passkeyRegistrationOptions(user))
	require.Empty(ts.T(), ts.identities(password))
}

func (ts *SCIMTestSuite) TestOldEmailCannotSignInAfterEmailChange() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, oktaUserWith("value", "alice.smith@example.com"))
	user := ts.linkedUser(id)
	require.Equal(ts.T(), "alice.smith@example.com", user.GetEmail())

	for _, email := range []string{"alice@example.com", "alice.smith@example.com"} {
		for _, req := range []struct{ path, body string }{
			{"/recover", `{"email":"` + email + `"}`},
			{"/otp", `{"email":"` + email + `","create_user":false}`},
			{"/magiclink", `{"email":"` + email + `"}`},
			{"/token?grant_type=password", `{"email":"` + email + `","password":"hunter2hunter2"}`},
		} {
			r := httptest.NewRequest(http.MethodPost, req.path, strings.NewReader(req.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, r)
			require.NotContains(ts.T(), w.Body.String(), "access_token", req.path)

			reloaded := ts.linkedUser(id)
			require.Nil(ts.T(), reloaded.RecoverySentAt, req.path)
			require.Empty(ts.T(), reloaded.RecoveryToken, req.path)
			require.Empty(ts.T(), reloaded.ConfirmationToken, req.path)
			require.Zero(ts.T(), ts.countRows(&models.OneTimeToken{}, "user_id = ?", user.ID), req.path)
			require.Zero(ts.T(), ts.sessions(user), req.path)
		}
	}
}

func (ts *SCIMTestSuite) TestReplaceChangesEmailAndClearsPendingTokens() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	user.RecoveryToken = "recovery-token-hash"
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "recovery_token"))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, user.ID, "alice@example.com", "recovery-token-hash", models.RecoveryToken, time.Hour, true))

	ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, oktaUserWith("value", "Alice.Smith@example.com"))

	reloaded := ts.linkedUser(id)
	require.Equal(ts.T(), "alice.smith@example.com", reloaded.GetEmail())
	require.Equal(ts.T(), "Alice.Smith@example.com", reloaded.UserMetaData["email"])
	require.Empty(ts.T(), reloaded.RecoveryToken)
	require.Zero(ts.T(), ts.countRows(&models.OneTimeToken{}, "user_id = ?", user.ID))
	require.Equal(ts.T(), "Alice.Smith@example.com", ts.ssoIdentity("Alice@Example.com").IdentityData["email"])
	require.Equal(ts.T(), user.ID, ts.signIn("saml-name-id", "alice.smith@example.com").ID)
}

func (ts *SCIMTestSuite) TestReplaceRenamesAndChangesEmail() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, withField(oktaUserWith("value", "alice.smith@example.com"), "userName", "alice.smith@example.com"))

	require.Equal(ts.T(), "alice.smith@example.com", ts.linkedUser(id).GetEmail())
	identities := ts.identities(user)
	require.Len(ts.T(), identities, 1)
	require.Equal(ts.T(), "alice.smith@example.com", identities[0].ProviderID)
	require.Equal(ts.T(), "alice.smith@example.com", identities[0].IdentityData["email"])
	require.Equal(ts.T(), user.ID, ts.signIn("saml-name-id", "alice.smith@example.com").ID)
}

func (ts *SCIMTestSuite) TestReplaceEmailUniqueWithinProvider() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob", "bob@example.com")
	ts.ssoUser(ts.B, "carol", "carol@example.com")

	require.Equal(ts.T(), "uniqueness", ts.expect(http.StatusConflict, http.MethodPut, "/Users/"+id, oktaUserWith("value", "Bob@example.com"))["scimType"])
	require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail())

	ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, oktaUserWith("value", "carol@example.com"))
	require.Equal(ts.T(), "carol@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestRemovingEmailsKeepsUserEmail() {
	id := ts.create(ts.TokenA, oktaUserWith("userName", "alice.smith"))
	user := ts.linkedUser(id)

	for _, userName := range []string{"alice.smith", "asmith"} {
		ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`","active":true}`)
		require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail(), userName)
		require.Equal(ts.T(), "alice@example.com", ts.ssoIdentity(userName).IdentityData["email"], userName)
		require.Equal(ts.T(), user.ID, ts.signIn("saml-name-id-"+userName, "alice@example.com").ID, userName)
	}
}

func (ts *SCIMTestSuite) TestCreateInactiveLogsOutWithoutBanning() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	ts.refreshToken(existing)

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUserWith("active", false)))

	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMTestSuite) TestCreateRejectsSharedUser() {
	ts.create(ts.TokenA, oktaUser)

	require.Equal(ts.T(), "uniqueness", ts.expect(http.StatusConflict, http.MethodPost, "/Users", oktaUserWith("userName", "alice.smith"))["scimType"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice.smith"`)["totalResults"])
}

func (ts *SCIMTestSuite) TestRejectsMissingOrInvalidEmails() {
	invalid := oktaUserWith("value", "not-an-email")
	require.Equal(ts.T(), "invalidValue", ts.expect(http.StatusBadRequest, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`)["scimType"])
	require.Equal(ts.T(), "invalidValue", ts.expect(http.StatusBadRequest, http.MethodPost, "/Users", invalid)["scimType"])

	id := ts.create(ts.TokenA, oktaUser)
	require.Equal(ts.T(), "invalidValue", ts.expect(http.StatusBadRequest, http.MethodPut, "/Users/"+id, invalid)["scimType"])
	require.Equal(ts.T(), "invalidValue", ts.expect(http.StatusBadRequest, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "path": "emails", "value": [{"value": "not-an-email", "primary": true}]}`))["scimType"])
	require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestCreateFallsBackToEmailUserName() {
	user := ts.linkedUser(ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com"}`))
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.Equal(ts.T(), user.ID, ts.signIn("saml-name-id", "alice@example.com").ID)
}

func (ts *SCIMTestSuite) TestCreateKeepsAdminBan() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), existing.Ban(ts.API.db, time.Hour))

	require.True(ts.T(), ts.linkedUser(ts.create(ts.TokenA, oktaUser)).IsBanned())
}

func (ts *SCIMTestSuite) TestCreateLeavesNoUserOnConflict() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	ts.expect(http.StatusConflict, http.MethodPost, "/Users", userWith("bob@example.com", "a-1"))
	require.Zero(ts.T(), ts.users("bob@example.com"))
}

func (ts *SCIMTestSuite) refreshToken(user *models.User) string {
	token, err := models.GrantAuthenticatedUser(ts.API.db, user, models.GrantParams{})
	require.NoError(ts.T(), err)
	return token.Token
}

func (ts *SCIMTestSuite) refresh(token string) int {
	r := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token", strings.NewReader(`{"refresh_token":"`+token+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w.Code
}

func (ts *SCIMTestSuite) sessions(user *models.User) int {
	return ts.countRows(&models.Session{}, "user_id = ?", user.ID)
}

func claims(sub, email string) *provider.UserProvidedData {
	return &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: sub, Email: email, EmailVerified: true},
		Emails:   []provider.Email{{Email: email, Primary: true, Verified: true}},
	}
}

func (ts *SCIMTestSuite) samlLogin(p *models.SSOProvider, sub, email string) (user *models.User, err error) {
	err = ts.API.db.Transaction(func(tx *storage.Connection) (terr error) {
		_, user, terr = ts.API.createAccountFromExternalIdentity(tx, httptest.NewRequest(http.MethodPost, "/sso/saml/acs", nil), claims(sub, email), ssoProviderType(p.ID), false)
		return terr
	})
	return user, err
}

func (ts *SCIMTestSuite) signIn(sub, email string) *models.User {
	user, err := ts.samlLogin(ts.A, sub, email)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMTestSuite) TestLoginAllowedWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, oktaUser)
	linked := ts.linkedUser(id)
	ts.setActive(id, false)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	require.Equal(ts.T(), linked.ID, ts.signIn("Alice@Example.com", "alice@example.com").ID)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, linked))
	require.Equal(ts.T(), "jit@example.com", ts.signIn("jit-user", "jit@example.com").GetEmail())
}

func (ts *SCIMTestSuite) TestSAMLLoginBlockedWhenCreatedInactive() {
	ts.linkedUser(ts.create(ts.TokenA, oktaUserWith("active", false)))

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowedWhenActiveOmitted() {
	linked := ts.linkedUser(ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com","emails":[{"primary":true,"value":"alice@example.com"}]}`))
	require.Equal(ts.T(), linked.ID, ts.signIn("Alice@Example.com", "alice@example.com").ID)
}

func (ts *SCIMTestSuite) TestLoginAllowedForSSOUserWithoutSCIMRow() {
	existing := ts.ssoUser(ts.A, "jit-user", "jit@example.com")

	require.Equal(ts.T(), existing.ID, ts.signIn("jit-user", "jit@example.com").ID)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, existing))
}

func (ts *SCIMTestSuite) TestSAMLLoginLinksDivergedNameIDToSCIMUser() {
	linked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	for range 2 {
		require.Equal(ts.T(), linked.ID, ts.signIn("saml-name-id", "alice@example.com").ID)
	}

	require.Equal(ts.T(), 1, ts.users("alice@example.com"))

	providerIDs := []string{}
	for _, identity := range ts.identities(linked) {
		require.Equal(ts.T(), ssoProviderType(ts.A.ID), identity.Provider)
		providerIDs = append(providerIDs, identity.ProviderID)
	}
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "saml-name-id"}, providerIDs)
}

func (ts *SCIMTestSuite) users(email string) int {
	return ts.countRows(&models.User{}, "email = ?", email)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowsJITWithoutSCIMToken() {
	user, err := ts.samlLogin(createSSOProvider(ts.T(), ts.API.db), "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "jit@example.com", user.GetEmail())
}

func (ts *SCIMTestSuite) TestSAMLLoginNotBlockedByOtherProvider() {
	id := ts.create(ts.TokenB, oktaUser)
	ts.setActiveAs(ts.TokenB, id, false)

	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.Equal(ts.T(), existing.ID, ts.signIn("Alice@Example.com", "alice@example.com").ID)
}

func (ts *SCIMTestSuite) issueSession(conn *storage.Connection, user *models.User) error {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	_, err := ts.API.tokenService.IssueRefreshToken(r, http.Header{}, conn, user, models.OAuth, models.GrantParams{})
	return err
}

func (ts *SCIMTestSuite) requireBanned(err error) {
	var httpErr *apierrors.HTTPError
	require.ErrorAs(ts.T(), err, &httpErr)
	require.Equal(ts.T(), http.StatusForbidden, httpErr.HTTPStatus)
	require.Equal(ts.T(), apierrors.ErrorCodeUserBanned, httpErr.ErrorCode)
}

func (ts *SCIMTestSuite) TestLoginAndSessionRefusedWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	require.Equal(ts.T(), user.ID, ts.signIn("Alice@Example.com", "alice@example.com").ID)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	ts.setActive(id, false)
	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
	_, err = ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.Error(ts.T(), err)
	require.Len(ts.T(), ts.identities(user), 1)
	ts.requireBanned(ts.issueSession(ts.API.db, user))
	require.Zero(ts.T(), ts.sessions(user))

	ts.setActive(id, true)
	require.Equal(ts.T(), user.ID, ts.signIn("Alice@Example.com", "alice@example.com").ID)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	ts.expect(http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")
	_, err = ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
	ts.requireBanned(ts.issueSession(ts.API.db, user))

	ts.expect(http.StatusConflict, http.MethodPost, "/Users", oktaUser)
	_, err = ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
	ts.requireBanned(ts.issueSession(ts.API.db, user))
}

func (ts *SCIMTestSuite) TestSessionRefusedForLinkedOAuthIdentityWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.addIdentity(user, "google", map[string]any{"sub": "google-sub", "email": "alice@example.com"})
	ts.setActive(id, false)

	err := ts.API.db.Transaction(func(tx *storage.Connection) error {
		_, found, terr := ts.API.createAccountFromExternalIdentity(tx, httptest.NewRequest(http.MethodGet, "/callback", nil), claims("google-sub", "alice@example.com"), "google", false)
		if terr != nil {
			return terr
		}
		require.Equal(ts.T(), user.ID, found.ID)
		return ts.issueSession(tx, found)
	})
	ts.requireBanned(err)
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMTestSuite) setActive(id string, active bool) {
	ts.setActiveAs(ts.TokenA, id, active)
}

func (ts *SCIMTestSuite) setActiveAs(token, id string, active bool) {
	w, _ := ts.do(token, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) TestReplaceDeactivatesAndReactivates() {
	id := ts.create(ts.TokenA, oktaUser)
	require.Equal(ts.T(), http.StatusOK, ts.refresh(ts.refreshToken(ts.linkedUser(id))))
	refreshToken := ts.refreshToken(ts.linkedUser(id))

	ts.setActive(id, false)
	user := ts.linkedUser(id)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))

	listed := ts.list(ts.TokenA, "")
	require.EqualValues(ts.T(), 1, listed["totalResults"])
	require.Equal(ts.T(), id, listed["Resources"].([]any)[0].(map[string]any)["id"])
	require.Equal(ts.T(), false, listed["Resources"].([]any)[0].(map[string]any)["active"])

	ts.setActive(id, true)
	require.False(ts.T(), ts.linkedUser(id).IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
}

func (ts *SCIMTestSuite) TestPutInactiveRevokesSessions() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	refreshToken := ts.refreshToken(user)

	require.Equal(ts.T(), false, ts.expect(http.StatusOK, http.MethodPut, "/Users/"+id, oktaUserWith("active", false))["active"])
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
	require.Len(ts.T(), ts.auditActions(models.SCIMUserUpdatedAction), 1)
}

func (ts *SCIMTestSuite) TestReplaceKeepsAdminBanWhenActiveDoesNotChange() {
	id := ts.create(ts.TokenA, oktaUser)
	require.NoError(ts.T(), ts.linkedUser(id).Ban(ts.API.db, time.Hour))

	ts.setActive(id, true)
	require.True(ts.T(), ts.linkedUser(id).IsBanned())
}

func (ts *SCIMTestSuite) TestReplaceLinksUnlinkedRow() {
	row, err := models.CreateSCIMUser(ts.API.db, ts.A.ID, []byte(`{"userName":"Alice@Example.com"}`))
	require.NoError(ts.T(), err)

	ts.expect(http.StatusOK, http.MethodPut, "/Users/"+row.ID.String(), oktaUserWith("active", false))

	user := ts.linkedUser(row.ID.String())
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.False(ts.T(), user.IsBanned())
}

func (ts *SCIMTestSuite) TestDeleteLogsOutWithoutBanning() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	refreshToken := ts.refreshToken(user)

	ts.expect(http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")

	user = ts.reloadUser(user.ID)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
}

func (ts *SCIMTestSuite) TestCreateRefusesUserDeletedByProviderSameUserName() {
	ts.requireCreateRefusedAfterProviderDelete(oktaUser)
}

func (ts *SCIMTestSuite) TestCreateRefusesUserDeletedByProviderNewUserName() {
	ts.requireCreateRefusedAfterProviderDelete(oktaUserWith("userName", "alice.new@example.com"))
}

func (ts *SCIMTestSuite) requireCreateRefusedAfterProviderDelete(body string) {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.expect(http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")

	require.Equal(ts.T(), "uniqueness", ts.expect(http.StatusConflict, http.MethodPost, "/Users", body)["scimType"])
	require.False(ts.T(), ts.reloadUser(user.ID).IsBanned())
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "user_id = ? AND deleted_at IS NULL", user.ID))
	require.Len(ts.T(), ts.identities(user), 1)
	require.Equal(ts.T(), 1, ts.users("alice@example.com"))
}

func (ts *SCIMTestSuite) TestCreateAfterAdminHardDeletesProviderDeletedUser() {
	ts.requireCreateAfterAdminDelete(false)
}

func (ts *SCIMTestSuite) TestCreateAfterAdminSoftDeletesProviderDeletedUser() {
	ts.requireCreateAfterAdminDelete(true)
}

func (ts *SCIMTestSuite) requireCreateAfterAdminDelete(soft bool) {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.expect(http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")
	w := serveAdmin(ts.T(), ts.API, http.MethodDelete, "/admin/users/"+user.ID.String(), map[string]any{"should_soft_delete": soft})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	created := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), user.ID, created.ID, soft)
	require.True(ts.T(), created.IsSSOUser, soft)
}

func (ts *SCIMTestSuite) rename(id, userName string, status int) {
	ts.expect(status, http.MethodPut, "/Users/"+id, oktaUserWith("userName", userName))
}

func (ts *SCIMTestSuite) TestReplaceRenamesSSOIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	ts.rename(id, "alice2@example.com", http.StatusOK)

	identity := ts.ssoIdentity("alice2@example.com")
	require.Equal(ts.T(), user.ID, identity.UserID)
	require.Equal(ts.T(), "alice2@example.com", identity.IdentityData["sub"])
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) providerIDs(user *models.User) []string {
	ids := []string{}
	for _, identity := range ts.identities(user) {
		ids = append(ids, identity.ProviderID)
	}
	return ids
}

func (ts *SCIMTestSuite) TestReplaceRenamesCaseOnly() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.signIn("alice@example.com", "alice@example.com")
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "alice@example.com"}, ts.providerIDs(user))

	ts.rename(id, "alice@example.com", http.StatusOK)
	ts.rename(id, "alice@example.com", http.StatusOK)
	require.Equal(ts.T(), []string{"alice@example.com"}, ts.providerIDs(user))
	require.Equal(ts.T(), user.ID, ts.signIn("alice@example.com", "alice@example.com").ID)
}

func (ts *SCIMTestSuite) TestReplaceRenameRemovesOldNameIDIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.signIn("alice@example.com", "alice@example.com")
	ts.signIn("saml-name-id", "alice@example.com")

	ts.rename(id, "bob@example.com", http.StatusOK)
	require.ElementsMatch(ts.T(), []string{"bob@example.com", "saml-name-id"}, ts.providerIDs(user))
	require.NotEqual(ts.T(), user.ID, ts.signIn("alice@example.com", "new-hire@example.com").ID)
}

func (ts *SCIMTestSuite) TestReplaceRejectsRenameToTakenIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob@example.com", "bob@example.com")

	ts.rename(id, "bob@example.com", http.StatusConflict)

	require.Equal(ts.T(), "alice@example.com", ts.scimRow(id).UserName)
	ts.ssoIdentity("Alice@Example.com")
}

func (ts *SCIMTestSuite) accessToken(user *models.User) string {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
	token, _, err := ts.API.generateAccessToken(httptest.NewRequest(http.MethodPost, "/token", nil), ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)
	return token
}

func (ts *SCIMTestSuite) unlink(user *models.User, identity *models.Identity) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodDelete, "/user/identities/"+identity.ID.String(), nil)
	r.Header.Set("Authorization", "Bearer "+ts.accessToken(user))
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
}

func (ts *SCIMTestSuite) TestUnlinkRefusedForSCIMManagedIdentity() {
	ts.API.config.Security.ManualLinkingEnabled = true
	defer func() { ts.API.config.Security.ManualLinkingEnabled = false }()
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.addIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})

	w := ts.unlink(user, ts.ssoIdentity("Alice@Example.com"))
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), string(apierrors.ErrorCodeUserSSOManaged))
	require.Len(ts.T(), ts.identities(user), 2)

	ts.rename(id, "alice2@example.com", http.StatusOK)
	sso := ts.ssoIdentity("alice2@example.com")

	ts.expect(http.StatusNoContent, http.MethodDelete, "/Users/"+id, "")
	w = ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) TestUnlinkAllowedWhileSCIMFlagOff() {
	ts.API.config.Security.ManualLinkingEnabled = true
	defer func() { ts.API.config.Security.ManualLinkingEnabled = false }()
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))
	ts.addIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	w := ts.unlink(user, ts.ssoIdentity("Alice@Example.com"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) TestRenameSkippedWhenIdentityMissing() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	require.NoError(ts.T(), ts.API.db.Destroy(ts.ssoIdentity("Alice@Example.com")))
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	entries := ts.auditDuring(func() { ts.rename(id, "alice2@example.com", http.StatusOK) })

	require.Equal(ts.T(), "alice2@example.com", ts.scimRow(id).UserName)
	require.Empty(ts.T(), ts.identities(user))
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), string(models.SCIMUserUpdatedAction), entries[0].Payload["action"])
	warned := slices.ContainsFunc(hook.AllEntries(), func(entry *logrus.Entry) bool {
		return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "identity not found")
	})
	require.True(ts.T(), warned)
	require.NotEqual(ts.T(), user.ID, ts.signIn("alice2@example.com", "alice@example.com").ID)
	require.Equal(ts.T(), 2, ts.users("alice@example.com"))
}

func (ts *SCIMTestSuite) TestBeforeUserCreatedHook() {
	require.NoError(ts.T(), ts.API.db.RawQuery(`CREATE OR REPLACE FUNCTION auth.scim_reject_signup(input jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{"error":{"http_code":403,"message":"signup blocked"}}'::jsonb $$`).Exec())
	hook := &ts.API.config.Hook.BeforeUserCreated
	hook.Enabled, hook.URI = true, "pg-functions://postgres/auth/scim_reject_signup"
	require.NoError(ts.T(), hook.PopulateExtensibilityPoint())
	defer func() { hook.Enabled = false }()

	require.Equal(ts.T(), "signup blocked", ts.expect(http.StatusForbidden, http.MethodPost, "/Users", oktaUser)["detail"])
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))

	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.Equal(ts.T(), existing.ID, ts.linkedUser(ts.create(ts.TokenA, oktaUser)).ID)
}
