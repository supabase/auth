package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/stretchr/testify/require"
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

func (ts *SCIMUsersTestSuite) TestCreateInactiveBansAndLogsOut() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	session, err := models.NewSession(existing.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	user := ts.linkedUser(ts.create(ts.TokenA, strings.Replace(oktaUser, `"active": true`, `"active": false`, 1)))

	require.True(ts.T(), user.IsBanned())
	count, err := ts.API.db.Q().Where("user_id = ?", user.ID).Count(&models.Session{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)
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
