package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const queryTimeout = 5 * time.Second

type Row struct {
	Resource
	References json.RawMessage `db:"refs"`
}

func (r Row) Into[T core.Resource](endpoint string) (T, error) {
	item, err := r.As[T](endpoint)
	if err != nil {
		return item, err
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(r.References, &parts); err != nil {
		return item, err
	}
	for _, part := range parts {
		if string(part) == "null" {
			continue
		}
		if err := json.Unmarshal(part, &item); err != nil {
			return item, err
		}
	}
	return item, nil
}

func Decode[T core.Resource](rows []Row, endpoint string) ([]T, error) {
	items := make([]T, len(rows))
	for i, row := range rows {
		item, err := row.Into[T](endpoint)
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

func Encode[T core.Resource](item T, references []query.Reference) (string, []Link, error) {
	document, err := core.NewObject(item)
	if err != nil {
		return "", nil, err
	}
	for _, key := range []string{"id", "meta", "password"} {
		document.Remove(key)
	}
	links := []Link{}
	for _, reference := range references {
		if types := reference.Targets(); types != nil {
			links = append(links, Link{reference.Name(), types, document.Get(reference.Name())})
		}
		reference.Strip(document)
	}
	raw, err := json.Marshal(document)
	return string(raw), links, err
}

type Search struct {
	Where     query.Clause
	Order     string
	OrderArgs []any
	Count     int
	Offset    int
	Refs      string
}

func (s Scope) Page(ctx context.Context, search Search) ([]Row, int, error) {
	rows, total, err := s.page(ctx, search)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, 0, scimerrors.ErrTooMany("the query took too long")
	}
	return rows, total, err
}

func (s Scope) page(ctx context.Context, search Search) ([]Row, int, error) {
	q := s.query(s.db)
	if search.Where != nil {
		text, args := search.Where.SQL()
		q = q.Where(text, args...)
	}
	if search.Count == 0 {
		total, err := s.count(ctx, q)
		return nil, total, err
	}
	sql, values := q.Select("id").Order(search.Order, search.OrderArgs...).ToSQL(pop.NewModel(&Resource{}, ctx))
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := s.fetch(s.db.WithContext(bounded), search.Refs, fmt.Sprintf("unnest(array(%s LIMIT $%d OFFSET $%d)) WITH ORDINALITY page(id, n) JOIN scim_resources USING (id) ORDER BY page.n", sql, len(values)+1, len(values)+2), append(values, search.Count, search.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	total := search.Offset + len(rows)
	if len(rows) == search.Count || (len(rows) == 0 && search.Offset > 0) {
		total, err = s.count(ctx, q)
	}
	return rows, total, err
}

func (s Scope) count(ctx context.Context, q *pop.Query) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	bounded := *q
	bounded.Connection = q.Connection.WithContext(ctx)
	return bounded.Count(&Resource{})
}

func (s Scope) Find(ctx context.Context, id uuid.UUID, refs string) (Row, error) {
	return s.find(ctx, s.db.WithContext(ctx), id, refs)
}

func (s Scope) find(ctx context.Context, tx *storage.Connection, id uuid.UUID, refs string) (Row, error) {
	sql, args := s.query(tx).Where("id = ?", id).Select("id").ToSQL(pop.NewModel(&Resource{}, ctx))
	rows, err := s.fetch(tx, refs, "scim_resources WHERE id = ("+sql+")", args...)
	if err != nil {
		return Row{}, err
	}
	if len(rows) == 0 {
		return Row{}, NotFound()
	}
	return rows[0], nil
}

func (s Scope) fetch(tx *storage.Connection, refs, from string, args ...any) ([]Row, error) {
	rows := []Row{}
	err := tx.RawQuery(fmt.Sprintf("SELECT %s, %s AS refs FROM %s", ResourceColumns, refs, from), args...).All(&rows)
	return rows, err
}

func NotFound() error {
	return scimerrors.ErrNotFound("Not found")
}

func unique(err error) error {
	if pg := utilities.NewPostgresError(err); pg != nil && pg.IsUniqueConstraintViolated() {
		return scimerrors.ErrUniqueness("resource must be unique")
	}
	return err
}
