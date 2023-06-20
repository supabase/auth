package models

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/storage/test"
)

type FactorTestSuite struct {
	suite.Suite
	db *storage.Connection
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
}

func (ts *FactorTestSuite) TestFindFactorByFactorID() {
	f := ts.createFactor()
	n, err := FindFactorByFactorID(ts.db, f.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), f.ID, n.ID)
	_, err = FindFactorByFactorID(ts.db, uuid.Nil)
	require.EqualError(ts.T(), err, FactorNotFoundError{}.Error())
}

func (ts *FactorTestSuite) createFactor() *Factor {
	user, err := NewUser("", "agenericemail@gmail.com", "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	factor, err := NewFactor(user, "asimplename", TOTP, FactorStateUnverified, "topsecret")
	require.NoError(ts.T(), err)

	err = ts.db.Create(factor)
	require.NoError(ts.T(), err)

	return factor
}
func (ts *FactorTestSuite) TestUpdateStatus() {
	newFactorStatus := FactorStateVerified
	u, err := NewUser("", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "", TOTP, FactorStateUnverified, "some-secret")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), f.UpdateStatus(ts.db, newFactorStatus))
	require.Equal(ts.T(), newFactorStatus.String(), f.Status)
}

func (ts *FactorTestSuite) TestUpdateFriendlyName() {
	newSimpleName := "newFactorName"
	u, err := NewUser("", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", TOTP, FactorStateUnverified, "some-secret")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), f.UpdateFriendlyName(ts.db, newSimpleName))
	require.Equal(ts.T(), newSimpleName, f.FriendlyName)
}

func (ts *FactorTestSuite) TestEncodedFactorDoesNotLeakSecret() {
	u, err := NewUser("", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", TOTP, FactorStateUnverified, "some-secret")
	require.NoError(ts.T(), err)
	encodedFactor, err := json.Marshal(f)
	require.NoError(ts.T(), err)
	decodedFactor := Factor{}
	json.Unmarshal(encodedFactor, &decodedFactor)
	require.Equal(ts.T(), decodedFactor.Secret, "")
}
