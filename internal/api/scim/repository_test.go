package scim

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage/test"
)

func TestRepositoryListPastDeadline(t *testing.T) {
	config, err := confload.LoadGlobal("../../../hack/test.env")
	require.NoError(t, err)
	db, err := test.SetupDBConnection(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	groups := NewRepository[*core.Group](db, "Group", map[string]string{}, core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)})
	ctx, cancel := context.WithDeadline(tokenKey.WithValue(context.Background(), &models.SCIMToken{}), time.Now().Add(-time.Second))
	defer cancel()

	for _, count := range []int{0, 10} {
		_, _, err := groups.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count})
		require.Equal(t, scimerrors.ErrTooMany("the query took too long"), err)
	}
}
