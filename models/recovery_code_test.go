package models

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type RecoveryCodeTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *RecoveryCodeTestSuite) SetupTest() {
	TruncateAll(ts.db)

}

func TestRecoveryCode(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &UserTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *RecoveryCodeTestSuite) TestFindValidRecoveryCodesByUser() {
	// TODO: Joel -- convert numRecoveryCodes and recoveryCodeLength into constants in mfa.go
	numRecoveryCodes := 8
	var expectedRecoveryCodes []string
	user, err := NewUser(uuid.Nil, "", "", "", "", nil)
	err = ts.db.Create(user)
	require.NoError(ts.T(), err)
	for i := 0; i <= numRecoveryCodes; i++ {
		rc := ts.createRecoveryCode(user)
		expectedRecoveryCodes = append(expectedRecoveryCodes, rc.RecoveryCode)
	}
	recoveryCodes, err := FindValidRecoveryCodesByUser(ts.db, user)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), numRecoveryCodes, len(recoveryCodes), fmt.Sprintf("Expected %d recovery codes but got %d", numRecoveryCodes, len(recoveryCodes)))

	for index, recoveryCode := range recoveryCodes {
		require.Equal(ts.T(), expectedRecoveryCodes[index], recoveryCode, "Recovery codes should match")
	}
}

func (ts *RecoveryCodeTestSuite) createRecoveryCode(u *User) *RecoveryCode {
	recoveryCodeLength := 8
	rc, err := NewRecoveryCode(u, crypto.SecureToken(recoveryCodeLength))
	require.NoError(ts.T(), err)
	err = ts.db.Create(rc)
	require.NoError(ts.T(), err)
	return rc
}
