package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkSCIMUser(t *testing.T) {
	db := setupSCIMTestDB(t)
	provider := createSCIMTestProvider(t, db)
	user, err := NewUser("", "bjensen@example.com", "", "test", nil)
	require.NoError(t, err)
	require.NoError(t, db.Create(user))

	row, err := CreateSCIMUser(db, provider.ID, []byte(`{"userName":"bjensen"}`))
	require.NoError(t, err)
	before := row.UpdatedAt
	require.NoError(t, LinkSCIMUser(db, row, user.ID))
	require.Equal(t, user.ID, *row.UserID)
	require.True(t, row.UpdatedAt.After(before))

	reloaded, err := FindSCIMUser(db, provider.ID, row.ID)
	require.NoError(t, err)
	require.Equal(t, row.UpdatedAt, reloaded.UpdatedAt)
	require.Equal(t, user.ID, *reloaded.UserID)

	second, err := CreateSCIMUser(db, provider.ID, []byte(`{"userName":"babs"}`))
	require.NoError(t, err)
	require.ErrorIs(t, LinkSCIMUser(db, second, user.ID), ErrSCIMUserLinked)
}
