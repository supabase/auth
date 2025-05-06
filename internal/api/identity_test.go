package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type IdentityTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestIdentity(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	ts := &IdentityTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()
	suite.Run(t, ts)
}

func (ts *IdentityTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("", "one@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
	require.NoError(ts.T(), u.Confirm(ts.API.db))

	// Create identity
	i, err := models.NewIdentity(u, "email", map[string]interface{}{
		"sub":   u.ID.String(),
		"email": u.GetEmail(),
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(i))

	// Create user with 2 identities
	u, err = models.NewUser("123456789", "two@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
	require.NoError(ts.T(), u.Confirm(ts.API.db))
	require.NoError(ts.T(), u.ConfirmPhone(ts.API.db))

	i, err = models.NewIdentity(u, "email", map[string]interface{}{
		"sub":   u.ID.String(),
		"email": u.GetEmail(),
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(i))

	i2, err := models.NewIdentity(u, "phone", map[string]interface{}{
		"sub":   u.ID.String(),
		"phone": u.GetPhone(),
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(i2))
}

func (ts *IdentityTestSuite) TestLinkIdentityToUser() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "one@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	ctx := withTargetUser(context.Background(), u)

	// link a valid identity
	testValidUserData := &provider.UserProvidedData{
		Metadata: &provider.Claims{
			Subject: "test_subject",
		},
	}
	// request is just used as a placeholder in the function
	r := httptest.NewRequest(http.MethodGet, "/identities", nil)
	u, err = ts.API.linkIdentityToUser(r, ctx, ts.API.db, testValidUserData, "test")
	require.NoError(ts.T(), err)

	// load associated identities for the user
	ts.API.db.Load(u, "Identities")
	require.Len(ts.T(), u.Identities, 2)
	require.Equal(ts.T(), u.AppMetaData["provider"], "email")
	require.Equal(ts.T(), u.AppMetaData["providers"], []string{"email", "test"})

	// link an already existing identity
	testExistingUserData := &provider.UserProvidedData{
		Metadata: &provider.Claims{
			Subject: u.ID.String(),
		},
	}
	u, err = ts.API.linkIdentityToUser(r, ctx, ts.API.db, testExistingUserData, "email")
	require.ErrorIs(ts.T(), err, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeIdentityAlreadyExists, "Identity is already linked"))
	require.Nil(ts.T(), u)
}

func (ts *IdentityTestSuite) TestUnlinkIdentityError() {
	ts.Config.Security.ManualLinkingEnabled = true
	userWithOneIdentity, err := models.FindUserByEmailAndAudience(ts.API.db, "one@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	userWithTwoIdentities, err := models.FindUserByEmailAndAudience(ts.API.db, "two@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	cases := []struct {
		desc          string
		user          *models.User
		identityId    uuid.UUID
		expectedError *HTTPError
	}{
		{
			desc:          "User must have at least 1 identity after unlinking",
			user:          userWithOneIdentity,
			identityId:    userWithOneIdentity.Identities[0].ID,
			expectedError: apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeSingleIdentityNotDeletable, "User must have at least 1 identity after unlinking"),
		},
		{
			desc:          "Identity doesn't exist",
			user:          userWithTwoIdentities,
			identityId:    uuid.Must(uuid.NewV4()),
			expectedError: apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeIdentityNotFound, "Identity doesn't exist"),
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			token := ts.generateAccessTokenAndSession(c.user)
			req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("/user/identities/%s", c.identityId), nil)
			require.NoError(ts.T(), err)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedError.HTTPStatus, w.Code)

			var data HTTPError
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			require.Equal(ts.T(), c.expectedError.Message, data.Message)
		})
	}
}

func (ts *IdentityTestSuite) TestUnlinkIdentity() {
	ts.Config.Security.ManualLinkingEnabled = true

	// we want to test 2 cases here: unlinking a phone identity and email identity from a user
	cases := []struct {
		desc string
		// the provider to be unlinked
		provider string
		// the remaining provider that should be linked to the user
		providerRemaining string
	}{
		{
			desc:              "Unlink phone identity successfully",
			provider:          "phone",
			providerRemaining: "email",
		},
		{
			desc:              "Unlink email identity successfully",
			provider:          "email",
			providerRemaining: "phone",
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			// teardown and reset the state of the db to prevent running into errors
			ts.SetupTest()
			u, err := models.FindUserByEmailAndAudience(ts.API.db, "two@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			identity, err := models.FindIdentityByIdAndProvider(ts.API.db, u.ID.String(), c.provider)
			require.NoError(ts.T(), err)

			token := ts.generateAccessTokenAndSession(u)
			req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("/user/identities/%s", identity.ID), nil)
			require.NoError(ts.T(), err)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)

			// sanity checks
			u, err = models.FindUserByID(ts.API.db, u.ID)
			require.NoError(ts.T(), err)
			require.Len(ts.T(), u.Identities, 1)
			require.Equal(ts.T(), u.Identities[0].Provider, c.providerRemaining)

			// conditional checks depending on the provider that was unlinked
			switch c.provider {
			case "phone":
				require.Equal(ts.T(), "", u.GetPhone())
				require.Nil(ts.T(), u.PhoneConfirmedAt)
			case "email":
				require.Equal(ts.T(), "", u.GetEmail())
				require.Nil(ts.T(), u.EmailConfirmedAt)
			}

			// user still has a phone / email identity linked so it should not be unconfirmed
			require.NotNil(ts.T(), u.ConfirmedAt)
		})
	}

}

func (ts *IdentityTestSuite) generateAccessTokenAndSession(u *models.User) string {
	s, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(s))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, u, &s.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)
	return token

}
