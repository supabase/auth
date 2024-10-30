package models

import (
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type SessionsTestSuite struct {
	suite.Suite
	db     *storage.Connection
	Config *conf.GlobalConfiguration
}

func (ts *SessionsTestSuite) SetupTest() {
	TruncateAll(ts.db)

	project_id := uuid.Must(uuid.NewV4())
	// Create a project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", project_id)).Exec(); err != nil {
		panic(err)
	}

	// Create the admin of the organization
	user, err := NewUser("", "admin@example.com", "test", ts.Config.JWT.Aud, nil, uuid.Nil, project_id)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.db.Create(user, "organization_id", "organization_role"), "Error creating user")

	// Create the organization
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization', '%s', '%s')", organization_id, project_id, user.ID)).Exec(); err != nil {
		panic(err)
	}

	// Set the user as the admin of the organization
	if err := ts.db.RawQuery(fmt.Sprintf("UPDATE auth.users SET organization_id = '%s', organization_role='admin' WHERE id = '%s'", organization_id, user.ID)).Exec(); err != nil {
		panic(err)
	}

	email := "test@example.com"
	user2, err := NewUser("", email, "secret", ts.Config.JWT.Aud, nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user2, "project_id", "organization_role")
	require.NoError(ts.T(), err)
}

func TestSession(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &SessionsTestSuite{
		db:     conn,
		Config: globalConfig,
	}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *SessionsTestSuite) TestFindBySessionIDWithForUpdate() {

	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud, id, uuid.Nil)
	require.NoError(ts.T(), err)
	session, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(session))

	found, err := FindSessionByID(ts.db, session.ID, true)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), session.ID, found.ID)
}

func (ts *SessionsTestSuite) AddClaimAndReloadSession(session *Session, claim AuthenticationMethod) *Session {
	err := AddClaimToSession(ts.db, session.ID, claim)
	require.NoError(ts.T(), err)
	session, err = FindSessionByID(ts.db, session.ID, false)
	require.NoError(ts.T(), err)
	return session
}

func (ts *SessionsTestSuite) TestCalculateAALAndAMR() {
	totalDistinctClaims := 3
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud, id, uuid.Nil)
	require.NoError(ts.T(), err)
	session, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(session))

	session = ts.AddClaimAndReloadSession(session, PasswordGrant)

	firstClaimAddedTime := time.Now()
	session = ts.AddClaimAndReloadSession(session, TOTPSignIn)

	_, _, err = session.CalculateAALAndAMR(u)
	require.NoError(ts.T(), err)

	session = ts.AddClaimAndReloadSession(session, TOTPSignIn)

	session = ts.AddClaimAndReloadSession(session, SSOSAML)

	aal, amr, err := session.CalculateAALAndAMR(u)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), AAL2, aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))

	found := false
	for _, claim := range session.AMRClaims {
		if claim.GetAuthenticationMethod() == TOTPSignIn.String() {
			require.True(ts.T(), firstClaimAddedTime.Before(claim.UpdatedAt))
			found = true
		}
	}

	for _, claim := range amr {
		if claim.Method == SSOSAML.String() {
			require.NotNil(ts.T(), claim.Provider)
		}
	}
	require.True(ts.T(), found)
}
