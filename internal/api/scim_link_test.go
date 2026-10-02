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

func (ts *SCIMTestSuite) ssoUser(provider *models.SSOProvider, sub, email string) *models.User {
	user, err := models.NewUser("", email, "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	user.IsSSOUser = true
	require.NoError(ts.T(), ts.API.db.Create(user))
	identity, err := models.NewIdentity(user, ssoProviderType(provider.ID), map[string]any{"sub": sub, "email": email})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	return user
}

func (ts *SCIMTestSuite) linkedUser(id string) *models.User {
	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.NotNil(ts.T(), row.UserID)
	user, err := models.FindUserByID(ts.API.db, *row.UserID)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMTestSuite) identities(user *models.User) []*models.Identity {
	identities, err := models.FindIdentitiesByUserID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	return identities
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
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
	other := ts.ssoUser(ts.B, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.NotEqual(ts.T(), other.ID, user.ID)
	require.Empty(ts.T(), ts.identities(password))
	require.Len(ts.T(), ts.identities(other), 1)
}

func (ts *SCIMTestSuite) TestCreateReusesSAMLIdentity() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) TestCreateLinksByEmailWithinProvider() {
	existing := ts.ssoUser(ts.A, "saml-name-id", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 2)
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

func (ts *SCIMTestSuite) TestPasswordUserWithSameEmailIsNeverLinked() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, ts.passkeyRegistrationOptions(user))
	reloaded := ts.reloadUser(password.ID)
	require.False(ts.T(), reloaded.IsSSOUser)
	require.Empty(ts.T(), ts.identities(reloaded))
}

func (ts *SCIMTestSuite) TestNonSSOUserWithSSOIdentityEmailIsNeverLinked() {
	ts.requireNonSSOUserNeverLinked("saml-name-id")
}

func (ts *SCIMTestSuite) TestNonSSOUserWithSSOIdentitySubjectIsNeverLinked() {
	ts.requireNonSSOUserNeverLinked("Alice@Example.com")
}

func (ts *SCIMTestSuite) requireNonSSOUserNeverLinked(sub string) {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
	identity, err := models.NewIdentity(password, ssoProviderType(ts.A.ID), map[string]any{"sub": sub, "email": "alice@example.com", "email_verified": true})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)

	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	reloaded := ts.reloadUser(password.ID)
	require.False(ts.T(), reloaded.IsSSOUser)
	require.Len(ts.T(), ts.identities(reloaded), 1)
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "user_id = ?", password.ID))
}

func (ts *SCIMTestSuite) TestLinkAccountKeepsUserSSO() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
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
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, ts.withEmail("alice.smith@example.com"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
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

func (ts *SCIMTestSuite) withEmail(email string) string {
	return oktaUserWith("value", email)
}

func (ts *SCIMTestSuite) TestReplaceChangesEmail() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, ts.withEmail("Alice.Smith@example.com"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	reloaded := ts.linkedUser(id)
	require.Equal(ts.T(), "alice.smith@example.com", reloaded.GetEmail())
	require.Equal(ts.T(), "Alice.Smith@example.com", reloaded.UserMetaData["email"])
	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "Alice.Smith@example.com", identity.IdentityData["email"])

	signedIn, err := ts.samlLogin(ts.A, "saml-name-id", "alice.smith@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMTestSuite) TestReplaceChangingEmailClearsPendingTokens() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	user.RecoveryToken = "recovery-token-hash"
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "recovery_token"))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, user.ID, "alice@example.com", "recovery-token-hash", models.RecoveryToken, time.Hour, true))

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, ts.withEmail("alice.smith@example.com"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	require.Empty(ts.T(), ts.reloadUser(user.ID).RecoveryToken)
	require.Zero(ts.T(), ts.countRows(&models.OneTimeToken{}, "user_id = ?", user.ID))
}

func (ts *SCIMTestSuite) TestReplaceRenamesAndChangesEmail() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	body := withField(ts.withEmail("alice.smith@example.com"), "userName", "alice.smith@example.com")
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, body)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	require.Equal(ts.T(), "alice.smith@example.com", ts.linkedUser(id).GetEmail())
	identities := ts.identities(user)
	require.Len(ts.T(), identities, 1)
	require.Equal(ts.T(), "alice.smith@example.com", identities[0].ProviderID)
	require.Equal(ts.T(), "alice.smith@example.com", identities[0].IdentityData["email"])

	signedIn, err := ts.samlLogin(ts.A, "saml-name-id", "alice.smith@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMTestSuite) TestReplaceRejectsEmailTakenInProvider() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob", "bob@example.com")

	w, body := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, ts.withEmail("Bob@example.com"))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestReplaceAllowsEmailTakenInAnotherProvider() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.B, "bob", "bob@example.com")

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, ts.withEmail("bob@example.com"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "bob@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestRemovingEmailsKeepsUserEmail() {
	id := ts.create(ts.TokenA, oktaUserWith("userName", "alice.smith"))
	user := ts.linkedUser(id)

	for _, userName := range []string{"alice.smith", "asmith"} {
		w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`","active":true}`)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

		require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail(), userName)
		identity, err := models.FindIdentityByIdAndProvider(ts.API.db, userName, ssoProviderType(ts.A.ID))
		require.NoError(ts.T(), err, userName)
		require.Equal(ts.T(), "alice@example.com", identity.IdentityData["email"], userName)

		signedIn, err := ts.samlLogin(ts.A, "saml-name-id-"+userName, "alice@example.com")
		require.NoError(ts.T(), err, userName)
		require.Equal(ts.T(), user.ID, signedIn.ID, userName)
	}
}

func (ts *SCIMTestSuite) TestCreateInactiveLogsOutWithoutBanning() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	ts.session(existing)

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUserWith("active", false)))

	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMTestSuite) TestCreateRejectsSharedUser() {
	ts.create(ts.TokenA, oktaUser)

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUserWith("userName", "alice.smith"))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice.smith"`)["totalResults"])
}

func (ts *SCIMTestSuite) TestCreateRequiresEmail() {
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
}

func (ts *SCIMTestSuite) TestCreateFallsBackToEmailUserName() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com"}`)
	user := ts.linkedUser(id)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())

	signedIn, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMTestSuite) TestRejectsInvalidEmailsValue() {
	invalid := oktaUserWith("value", "not-an-email")
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", invalid)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])

	id := ts.create(ts.TokenA, oktaUser)
	w, body = ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, invalid)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])

	w, body = ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "path": "emails", "value": [{"value": "not-an-email", "primary": true}]}`))
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
	require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestCreateKeepsAdminBan() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), existing.Ban(ts.API.db, time.Hour))

	require.True(ts.T(), ts.linkedUser(ts.create(ts.TokenA, oktaUser)).IsBanned())
}

func (ts *SCIMTestSuite) TestCreateLeavesNoUserOnConflict() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	w, _ := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("bob@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code)
	require.Zero(ts.T(), ts.users("bob@example.com"))
}

func (ts *SCIMTestSuite) session(user *models.User) {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
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

func (ts *SCIMTestSuite) samlLogin(ssoProvider *models.SSOProvider, sub, email string) (*models.User, error) {
	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{
			Subject:       sub,
			Email:         email,
			EmailVerified: true,
		},
		Emails: []provider.Email{{
			Email:    email,
			Primary:  true,
			Verified: true,
		}},
	}
	return ts.samlLoginWith(ssoProvider, userData)
}

func (ts *SCIMTestSuite) samlLoginWith(ssoProvider *models.SSOProvider, userData *provider.UserProvidedData) (*models.User, error) {
	r := httptest.NewRequest(http.MethodPost, "/sso/saml/acs", nil)

	var user *models.User
	err := ts.API.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		_, user, terr = ts.API.createAccountFromExternalIdentity(tx, r, userData, ssoProviderType(ssoProvider.ID), false)
		return terr
	})
	return user, err
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowedForActiveSCIMUser() {
	id := ts.create(ts.TokenA, oktaUser)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowedForDeprovisionedUserWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, oktaUser)
	linked := ts.linkedUser(id)
	ts.setActive(id, false)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMTestSuite) TestSAMLLoginBlockedWhilePATCHedInactive() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.setActive(id, false)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)

	ts.setActive(id, true)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMTestSuite) TestSAMLLoginBlockedAfterDelete() {
	id := ts.create(ts.TokenA, oktaUser)

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)

	w, _ = ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusConflict, w.Code)
	_, err = ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
}

func (ts *SCIMTestSuite) TestSAMLLoginBlockedWhenCreatedInactive() {
	id := ts.create(ts.TokenA, oktaUserWith("active", false))
	ts.linkedUser(id)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowedWhenActiveOmitted() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com","emails":[{"primary":true,"value":"alice@example.com"}]}`)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowedWithoutSCIMRow() {
	existing := ts.ssoUser(ts.A, "jit-user", "jit@example.com")

	user, err := ts.samlLogin(ts.A, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), existing.ID, user.ID)
}

func (ts *SCIMTestSuite) TestSAMLLoginLinksDivergedNameIDToSCIMUser() {
	linked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	for range 2 {
		user, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), linked.ID, user.ID)
	}

	require.Equal(ts.T(), 1, ts.users("alice@example.com"))

	providerIDs := []string{}
	for _, identity := range ts.identities(linked) {
		require.Equal(ts.T(), ssoProviderType(ts.A.ID), identity.Provider)
		providerIDs = append(providerIDs, identity.ProviderID)
	}
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "saml-name-id"}, providerIDs)
}

func (ts *SCIMTestSuite) TestSAMLLoginBlockedForDivergedNameIDWhileInactive() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.setActive(id, false)
	linked := ts.linkedUser(id)

	_, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.Error(ts.T(), err)
	require.Len(ts.T(), ts.identities(linked), 1)
}

func (ts *SCIMTestSuite) users(email string) int {
	return ts.countRows(&models.User{}, "email = ?", email)
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowsJITWithoutSCIMToken() {
	provider := createSSOProvider(ts.T(), ts.API.db)

	user, err := ts.samlLogin(provider, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "jit@example.com", user.GetEmail())
}

func (ts *SCIMTestSuite) TestSAMLLoginAllowsJITWhileSCIMFlagOff() {
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	user, err := ts.samlLogin(ts.A, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "jit@example.com", user.GetEmail())
}

func (ts *SCIMTestSuite) TestSAMLLoginNotBlockedByOtherProvider() {
	id := ts.create(ts.TokenB, oktaUser)
	ts.setActiveAs(ts.TokenB, id, false)

	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), existing.ID, user.ID)
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

func (ts *SCIMTestSuite) TestSessionRefusedWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	ts.setActive(id, false)
	ts.requireBanned(ts.issueSession(ts.API.db, user))
	require.Zero(ts.T(), ts.sessions(user))

	ts.setActive(id, true)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	ts.requireBanned(ts.issueSession(ts.API.db, user))

	w, _ = ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusConflict, w.Code)
	ts.requireBanned(ts.issueSession(ts.API.db, user))
}

func (ts *SCIMTestSuite) TestSessionAllowedWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.setActive(id, false)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))
}

func (ts *SCIMTestSuite) TestSessionRefusedForLinkedOAuthIdentityWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	identity, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-sub", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	ts.setActive(id, false)

	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: "google-sub", Email: "alice@example.com", EmailVerified: true},
		Emails:   []provider.Email{{Email: "alice@example.com", Primary: true, Verified: true}},
	}
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		_, found, terr := ts.API.createAccountFromExternalIdentity(tx, httptest.NewRequest(http.MethodGet, "/callback", nil), userData, "google", false)
		if terr != nil {
			return terr
		}
		require.Equal(ts.T(), user.ID, found.ID)
		return ts.issueSession(tx, found)
	})
	ts.requireBanned(err)
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMTestSuite) TestSessionAllowedForSSOUserWithoutSCIMRow() {
	user := ts.ssoUser(ts.A, "saml-sub", "carol@example.com")
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))
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

	w, got := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, oktaUserWith("active", false))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, got["active"])
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

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+row.ID.String(), oktaUserWith("active", false))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	user := ts.linkedUser(row.ID.String())
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.False(ts.T(), user.IsBanned())
}

func (ts *SCIMTestSuite) TestDeleteLogsOutWithoutBanning() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	refreshToken := ts.refreshToken(user)

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

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
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	w, got := ts.do(ts.TokenA, http.MethodPost, "/Users", body)

	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", got["scimType"])
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
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w = serveAdmin(ts.T(), ts.API, http.MethodDelete, "/admin/users/"+user.ID.String(), map[string]any{"should_soft_delete": soft})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	created := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), user.ID, created.ID, soft)
	require.True(ts.T(), created.IsSSOUser, soft)
}

func (ts *SCIMTestSuite) rename(id, userName string) (int, string) {
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, oktaUserWith("userName", userName))
	return w.Code, w.Body.String()
}

func (ts *SCIMTestSuite) TestReplaceRenamesSSOIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)

	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "alice2@example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
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
	_, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "alice@example.com"}, ts.providerIDs(user))

	for range 2 {
		code, body := ts.rename(id, "alice@example.com")
		require.Equal(ts.T(), http.StatusOK, code, body)
	}
	require.Equal(ts.T(), []string{"alice@example.com"}, ts.providerIDs(user))

	signedIn, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMTestSuite) TestReplaceRenameRemovesOldNameIDIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	_, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	_, err = ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.NoError(ts.T(), err)

	code, body := ts.rename(id, "bob@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)
	require.ElementsMatch(ts.T(), []string{"bob@example.com", "saml-name-id"}, ts.providerIDs(user))

	signedIn, err := ts.samlLogin(ts.A, "alice@example.com", "new-hire@example.com")
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMTestSuite) TestReplaceRejectsRenameToTakenIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob@example.com", "bob@example.com")

	code, body := ts.rename(id, "bob@example.com")
	require.Equal(ts.T(), http.StatusConflict, code, body)

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.Equal(ts.T(), "alice@example.com", row.UserName)
	_, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
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
	google, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(google))
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)

	w := ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), string(apierrors.ErrorCodeUserSSOManaged))
	require.Len(ts.T(), ts.identities(user), 2)

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)
	sso, err = models.FindIdentityByIdAndProvider(ts.API.db, "alice2@example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w = ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) TestUnlinkAllowedWhileSCIMFlagOff() {
	ts.API.config.Security.ManualLinkingEnabled = true
	defer func() { ts.API.config.Security.ManualLinkingEnabled = false }()
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))
	google, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(google))
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	w := ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMTestSuite) TestRenameSkippedWhenIdentityMissing() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", ssoProviderType(ts.A.ID))
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Destroy(sso))
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	entries := ts.auditDuring(func() {
		code, body := ts.rename(id, "alice2@example.com")
		require.Equal(ts.T(), http.StatusOK, code, body)
	})

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.Equal(ts.T(), "alice2@example.com", row.UserName)
	require.Empty(ts.T(), ts.identities(user))
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), string(models.SCIMUserUpdatedAction), entries[0].Payload["action"])
	warned := slices.ContainsFunc(hook.AllEntries(), func(entry *logrus.Entry) bool {
		return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "identity not found")
	})
	require.True(ts.T(), warned)

	signedIn, err := ts.samlLogin(ts.A, "alice2@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), user.ID, signedIn.ID)
	require.Equal(ts.T(), 2, ts.users("alice@example.com"))
}

func (ts *SCIMTestSuite) TestBeforeUserCreatedHook() {
	require.NoError(ts.T(), ts.API.db.RawQuery(`CREATE OR REPLACE FUNCTION auth.scim_reject_signup(input jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{"error":{"http_code":403,"message":"signup blocked"}}'::jsonb $$`).Exec())
	hook := &ts.API.config.Hook.BeforeUserCreated
	hook.Enabled, hook.URI = true, "pg-functions://postgres/auth/scim_reject_signup"
	require.NoError(ts.T(), hook.PopulateExtensibilityPoint())
	defer func() { hook.Enabled = false }()

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusForbidden, w.Code, w.Body.String())
	require.Equal(ts.T(), "signup blocked", body["detail"])
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))

	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.Equal(ts.T(), existing.ID, ts.linkedUser(ts.create(ts.TokenA, oktaUser)).ID)
}
