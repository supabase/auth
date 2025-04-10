package models

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type FactorTestSuite struct {
	suite.Suite
	db         *storage.Connection
	TestFactor *Factor
}

func TestFactor(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &FactorTestSuite{
		db: conn,
	}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *FactorTestSuite) SetupTest() {
	TruncateAll(ts.db)
	user, err := NewUser("", "agenericemail@gmail.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))

	factor := NewTOTPFactor(user, "asimplename")
	require.NoError(ts.T(), factor.SetSecret("topsecret", false, "", ""))
	require.NoError(ts.T(), ts.db.Create(factor))
	ts.TestFactor = factor
}

func (ts *FactorTestSuite) TestFindFactorByFactorID() {
	n, err := FindFactorByFactorID(ts.db, ts.TestFactor.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), ts.TestFactor.ID, n.ID)

	_, err = FindFactorByFactorID(ts.db, uuid.Nil)
	require.EqualError(ts.T(), err, FactorNotFoundError{}.Error())
}

func (ts *FactorTestSuite) TestUpdateStatus() {
	newFactorStatus := FactorStateVerified
	require.NoError(ts.T(), ts.TestFactor.UpdateStatus(ts.db, newFactorStatus))
	require.Equal(ts.T(), newFactorStatus.String(), ts.TestFactor.Status)
}

func (ts *FactorTestSuite) TestUpdateFriendlyName() {
	newName := "newfactorname"
	require.NoError(ts.T(), ts.TestFactor.UpdateFriendlyName(ts.db, newName))
	require.Equal(ts.T(), newName, ts.TestFactor.FriendlyName)
}

func (ts *FactorTestSuite) TestEncodedFactorDoesNotLeakSecret() {
	encodedFactor, err := json.Marshal(ts.TestFactor)
	require.NoError(ts.T(), err)

	decodedFactor := Factor{}
	json.Unmarshal(encodedFactor, &decodedFactor)
	require.Equal(ts.T(), decodedFactor.Secret, "")
}
