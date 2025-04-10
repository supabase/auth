package storage

import (
	"errors"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

type TestUser struct {
	ID    uuid.UUID
	Role  string `db:"role"`
	Other string `db:"othercol"`
}

func TestGetExcludedColumns(t *testing.T) {
	u := TestUser{}
	cols, err := getExcludedColumns(u, "role")
	require.NoError(t, err)
	require.NotContains(t, cols, "role")
	require.Contains(t, cols, "othercol")
}

func TestGetExcludedColumns_InvalidName(t *testing.T) {
	u := TestUser{}
	_, err := getExcludedColumns(u, "adsf")
	require.Error(t, err)
}

func TestTransaction(t *testing.T) {
	apiTestConfig := "../../hack/test.env"
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	conn, err := Dial(config)
	require.NoError(t, err)
	require.NotNil(t, conn)

	defer func() {
		// clean up the test table created
		require.NoError(t, conn.RawQuery("drop table if exists test").Exec(), "Error removing table")
	}()

	commitWithError := NewCommitWithError(errors.New("commit with error"))
	err = conn.Transaction(func(tx *Connection) error {
		require.NoError(t, tx.RawQuery("create table if not exists test()").Exec(), "Error saving creating test table")
		return commitWithError
	})
	require.Error(t, err)
	require.ErrorIs(t, err, commitWithError)

	type TestData struct{}

	// check that transaction is still being committed despite returning an error above
	data := []TestData{}
	err = conn.RawQuery("select * from test").All(&data)
	require.NoError(t, err)
	require.Empty(t, data)
}
