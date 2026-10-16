package store

import (
	"context"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const queryTimeout = 5 * time.Second

const pageOfResources = `unnest(array(%s LIMIT $%d OFFSET $%d)) WITH ORDINALITY page(id, n)
JOIN scim_resources USING (id)
ORDER BY page.n`

func (sc scope) page(ctx context.Context, request *protocol.SearchRequest, refs []store.Reference) ([]store.Record, int, error) {
	found, err := sc.Search(request)
	if err != nil {
		return nil, 0, err
	}
	q := sc.query(sc.db.conn)
	if found.Where != nil {
		text, args := found.Where.SQL()
		q = q.Where("("+text+")", args...)
	}
	if request.Count == 0 {
		total, err := sc.count(ctx, q)
		return nil, total, err
	}
	offset := request.Offset()
	sql, values := q.Select("id").Order(found.Order, found.OrderArgs...).ToSQL(pop.NewModel(&model{}, ctx))
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := sc.fetch(sc.db.conn.WithContext(bounded), selection(refs), fmt.Sprintf(pageOfResources, sql, len(values)+1, len(values)+2), append(values, request.Count, offset)...)
	if err != nil {
		return nil, 0, err
	}
	total := offset + len(rows)
	if len(rows) == request.Count || (len(rows) == 0 && offset > 0) {
		total, err = sc.count(ctx, q)
	}
	if err != nil {
		return nil, 0, err
	}
	return records(rows), total, nil
}

func (sc scope) count(ctx context.Context, q *pop.Query) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	bounded := *q
	bounded.Connection = q.Connection.WithContext(ctx)
	return bounded.Count(&model{})
}

func (sc scope) query(tx *storage.Connection) *pop.Query {
	return tx.Q().Where(scopeWhere, sc.providerID, sc.Type)
}
