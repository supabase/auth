package models

import (
	"fmt"
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

func (ts *RecoveryCodeTestSuite) TestFindValidRecoveryCodesByFactor() {
	var expectedRecoveryCodes []string
	factor, err := NewFactor(nil, "", Recovery, FactorStateUnverified, "secret")
	require.NoError(ts.T(), err)
	err = ts.db.Create(factor)
	require.NoError(ts.T(), err)
	for i := 0; i <= NumRecoveryCodes; i++ {
		rc := ts.createRecoveryCode(factor)
		expectedRecoveryCodes = append(expectedRecoveryCodes, rc.RecoveryCode)
	}
	recoveryCodes, err := FindValidRecoveryCodesByFactor(ts.db, factor)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), NumRecoveryCodes, len(recoveryCodes), fmt.Sprintf("Expected %d recovery codes but got %d", NumRecoveryCodes, len(recoveryCodes)))

	for index, recoveryCode := range recoveryCodes {
		require.Equal(ts.T(), expectedRecoveryCodes[index], recoveryCode, "Recovery codes should match")
	}
}

func (ts *RecoveryCodeTestSuite) createRecoveryCode(rf *Factor) *RecoveryCode {
	rc, err := NewRecoveryCode(rf.ID, crypto.SecureToken(RecoveryCodeLength))
	require.NoError(ts.T(), err)
	err = ts.db.Create(rc)
	require.NoError(ts.T(), err)
	return rc
}
