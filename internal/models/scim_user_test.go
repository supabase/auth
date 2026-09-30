package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkNewSCIMUserBumpsVersion(t *testing.T) {
	db := setupSCIMTestDB(t)
	provider := createSCIMTestProvider(t, db)

	row, err := CreateSCIMUser(db, provider.ID, []byte(`{"userName":"alice"}`))
	require.NoError(t, err)
	before := row.UpdatedAt

	user, err := NewUser("", "alice@example.com", "", "test", nil)
	require.NoError(t, err)
	require.NoError(t, db.Create(user))

	require.NoError(t, LinkNewSCIMUser(db, row, user.ID))
	require.Equal(t, user.ID, *row.UserID)
	require.True(t, row.UpdatedAt.After(before))

	reloaded, err := FindSCIMUser(db, provider.ID, row.ID)
	require.NoError(t, err)
	require.Equal(t, row.UpdatedAt, reloaded.UpdatedAt)
	require.Equal(t, user.ID, *reloaded.UserID)
}
