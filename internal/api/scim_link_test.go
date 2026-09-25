package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
)

func (ts *SCIMUsersTestSuite) ssoUser(provider *models.SSOProvider, sub, email string) *models.User {
	user, err := models.NewUser("", email, "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	user.IsSSOUser = true
	require.NoError(ts.T(), ts.API.db.Create(user))
	identity, err := models.NewIdentity(user, "sso:"+provider.ID.String(), map[string]any{"sub": sub, "email": email})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	return user
}

func (ts *SCIMUsersTestSuite) linkedUser(id string) *models.User {
	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.NotNil(ts.T(), row.UserID)
	user, err := models.FindUserByID(ts.API.db, *row.UserID)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMUsersTestSuite) identities(user *models.User) []*models.Identity {
	identities, err := models.FindIdentitiesByUserID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	return identities
}

func (ts *SCIMUsersTestSuite) TestCreateProvisionsSSOUser() {
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.Equal(ts.T(), ts.API.config.JWT.Aud, user.Aud)
	require.NotNil(ts.T(), user.EmailConfirmedAt)
	require.False(ts.T(), user.IsBanned())
	require.Equal(ts.T(), []any{"sso:" + ts.A.ID.String()}, user.AppMetaData["providers"])

	identities := ts.identities(user)
	require.Len(ts.T(), identities, 1)
	require.Equal(ts.T(), "sso:"+ts.A.ID.String(), identities[0].Provider)
	require.Equal(ts.T(), "Alice@Example.com", identities[0].ProviderID)
}

func (ts *SCIMUsersTestSuite) TestCreateDoesNotLinkOutsideProvider() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
	other := ts.ssoUser(ts.B, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.NotEqual(ts.T(), other.ID, user.ID)
	require.Len(ts.T(), ts.identities(password), 0)
	require.Len(ts.T(), ts.identities(other), 1)
}

func (ts *SCIMUsersTestSuite) TestCreateReusesSAMLIdentity() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) TestCreateLinksByEmailWithinProvider() {
	existing := ts.ssoUser(ts.A, "saml-name-id", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 2)
}

func (ts *SCIMUsersTestSuite) TestCreateInactiveLogsOutWithoutBanning() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	ts.session(existing)

	user := ts.linkedUser(ts.create(ts.TokenA, strings.Replace(oktaUser, `"active": true`, `"active": false`, 1)))

	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMUsersTestSuite) TestCreateRejectsSharedUser() {
	ts.create(ts.TokenA, oktaUser)

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", strings.Replace(oktaUser, `"userName": "Alice@Example.com"`, `"userName": "alice.smith"`, 1))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice.smith"`)["totalResults"])
}

func (ts *SCIMUsersTestSuite) TestCreateRequiresEmail() {
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
}

func (ts *SCIMUsersTestSuite) TestCreateKeepsAdminBan() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), existing.Ban(ts.API.db, time.Hour))

	require.True(ts.T(), ts.linkedUser(ts.create(ts.TokenA, oktaUser)).IsBanned())
}

func (ts *SCIMUsersTestSuite) TestCreateLeavesNoUserOnConflict() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	w, _ := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("bob@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code)
	count, err := ts.API.db.Q().Where("email = ?", "bob@example.com").Count(&models.User{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)
}

func (ts *SCIMUsersTestSuite) session(user *models.User) {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
}

func (ts *SCIMUsersTestSuite) sessions(user *models.User) int {
	count, err := ts.API.db.Q().Where("user_id = ?", user.ID).Count(&models.Session{})
	require.NoError(ts.T(), err)
	return count
}

func (ts *SCIMUsersTestSuite) setActive(id string, active bool) {
	w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}]
	}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}

func (ts *SCIMUsersTestSuite) TestReplaceDeactivatesAndReactivates() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.session(ts.linkedUser(id))

	ts.setActive(id, false)
	user := ts.linkedUser(id)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))

	ts.setActive(id, true)
	require.False(ts.T(), ts.linkedUser(id).IsBanned())
}

func (ts *SCIMUsersTestSuite) TestReplaceKeepsAdminBanWhenActiveDoesNotChange() {
	id := ts.create(ts.TokenA, oktaUser)
	require.NoError(ts.T(), ts.linkedUser(id).Ban(ts.API.db, time.Hour))

	ts.setActive(id, true)
	require.True(ts.T(), ts.linkedUser(id).IsBanned())
}

func (ts *SCIMUsersTestSuite) TestReplaceLinksUnlinkedRow() {
	row, err := models.CreateSCIMUser(ts.API.db, ts.A.ID, []byte(`{"userName":"Alice@Example.com"}`))
	require.NoError(ts.T(), err)

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+row.ID.String(), strings.Replace(oktaUser, `"active": true`, `"active": false`, 1))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	user := ts.linkedUser(row.ID.String())
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.False(ts.T(), user.IsBanned())
}

func (ts *SCIMUsersTestSuite) TestDeleteLogsOutWithoutBanning() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.session(user)

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	user, err := models.FindUserByID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMUsersTestSuite) TestCreateDoesNotBanAfterDelete() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	relinked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), user.ID, relinked.ID)
	require.False(ts.T(), relinked.IsBanned())
}

func (ts *SCIMUsersTestSuite) TestCreateConcurrentSameEmailLinksToOneUser() {
	body := func(userName, externalID string) string {
		return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + externalID + `","emails":[{"primary":true,"value":"race@example.com"}]}`
	}
	bodies := []string{body("race-a", "race-a"), body("race-b", "race-b")}

	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, len(bodies))
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(bodies[i]))
			r.Header.Set("Authorization", "Bearer "+ts.TokenA)
			r.Header.Set("Content-Type", protocol.MediaType)
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, r)
			codes[i] = w.Code
		}(i)
	}
	close(start)
	wg.Wait()

	// The lock serializes the two creates: whichever commits first creates the
	// user, the other observes that account under the same provider and is
	// rejected as already linked -- never silently creating a second user.
	created := 0
	for _, code := range codes {
		if code == http.StatusCreated {
			created++
		} else {
			require.Equal(ts.T(), http.StatusConflict, code)
		}
	}
	require.Equal(ts.T(), 1, created)

	count, err := ts.API.db.Q().Where("email = ?", "race@example.com").Count(&models.User{})
	require.NoError(ts.T(), err)
	require.EqualValues(ts.T(), 1, count)
}

func (ts *SCIMUsersTestSuite) rename(id, userName string) (int, string) {
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, strings.Replace(oktaUser, `"userName": "Alice@Example.com"`, `"userName": "`+userName+`"`, 1))
	return w.Code, w.Body.String()
}

func (ts *SCIMUsersTestSuite) TestReplaceRenamesSSOIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)

	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "alice2@example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, identity.UserID)
	require.Equal(ts.T(), "alice2@example.com", identity.IdentityData["sub"])
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) TestReplaceRejectsRenameToTakenIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob@example.com", "bob@example.com")

	code, body := ts.rename(id, "bob@example.com")
	require.Equal(ts.T(), http.StatusConflict, code, body)

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.Equal(ts.T(), "alice@example.com", row.UserName)
	_, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
}
