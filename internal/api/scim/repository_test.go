package scim

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage/test"
)

func newGroups(t *testing.T) server.Repository[*core.Group] {
	config, err := confload.LoadGlobal("../../../hack/test.env")
	require.NoError(t, err)
	db, err := test.SetupDBConnection(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return NewRepository[*core.Group](db, "Group", map[string]string{}, core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)})
}

func TestRepositoryListPastDeadline(t *testing.T) {
	groups := newGroups(t)
	ctx, cancel := context.WithDeadline(tokenKey.WithValue(context.Background(), &models.SCIMToken{}), time.Now().Add(-time.Second))
	defer cancel()

	for _, count := range []int{0, 10} {
		_, _, err := groups.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count})
		require.Equal(t, scimerrors.ErrTooMany("the query took too long"), err)
	}
}

func TestRepositoryListReusesThePageSQL(t *testing.T) {
	groups := newGroups(t)
	ctx := tokenKey.WithValue(context.Background(), &models.SCIMToken{})
	pages := []string{}
	pop.SetTxLogger(func(_ logging.Level, _ any, sql string, _ ...any) {
		if strings.Contains(sql, "WITH ORDINALITY") {
			pages = append(pages, sql)
		}
	})
	defer pop.SetTxLogger(func(logging.Level, any, string, ...any) {})

	for _, start := range []int{1, 11} {
		_, _, err := groups.List(ctx, &protocol.SearchRequest{StartIndex: start, Count: 10})
		require.NoError(t, err)
	}
	require.Len(t, pages, 2)
	require.Equal(t, pages[0], pages[1])
}
