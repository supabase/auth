package api

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
