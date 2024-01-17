package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
	u, err := models.NewUser("", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	// Create identity
	i, err := models.NewIdentity(u, "email", map[string]interface{}{
		"sub":   u.ID.String(),
		"email": u.GetEmail(),
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(i))
}

func (ts *IdentityTestSuite) TestLinkIdentityToUser() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	ctx := withTargetUser(context.Background(), u)

	// link a valid identity
	testValidUserData := &provider.UserProvidedData{
		Metadata: &provider.Claims{
			Subject: "test_subject",
		},
	}
	u, err = ts.API.linkIdentityToUser(ctx, ts.API.db, testValidUserData, "test")
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
	u, err = ts.API.linkIdentityToUser(ctx, ts.API.db, testExistingUserData, "email")
	require.ErrorIs(ts.T(), err, unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked"))
	require.Nil(ts.T(), u)
}
