package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const queryTimeout = 5 * time.Second

const resourceColumns = "id, resource_type, resource, created_at, updated_at"

type Scope struct {
	db           *storage.Connection
	providerID   uuid.UUID
	resourceType string
	refs         string
}

func NewScope(db *storage.Connection, provider uuid.UUID, resourceType, refs string) Scope {
	return Scope{db: db, providerID: provider, resourceType: resourceType, refs: refs}
}

func (s Scope) Page(ctx context.Context, search Search) ([]Row, int, error) {
	rows, total, err := s.page(ctx, search)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, 0, scimerrors.ErrTooMany("the query took too long")
	}
	return rows, total, err
}

func (s Scope) Find(ctx context.Context, id uuid.UUID) (Row, error) {
	return s.find(ctx, s.db.WithContext(ctx), id)
}

func (s Scope) Create(ctx context.Context, document string, links []Link) (Row, error) {
	row, err := s.write(ctx, links, func(tx *storage.Connection) (*Resource, error) {
		return s.create(tx, document)
	})
	return row, conflict(err)
}

func (s Scope) Update(ctx context.Context, id uuid.UUID, document, version string, links []Link) (Row, error) {
	row, err := s.write(ctx, links, func(tx *storage.Connection) (*Resource, error) {
		return s.update(tx, id, document, guard(document, version, links))
	})
	if models.IsNotFoundError(err) {
		return row, s.missing(ctx, id)
	}
	return row, conflict(err)
}

func (s Scope) Delete(ctx context.Context, id uuid.UUID, version string) error {
	err := s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := s.remove(tx, id, version); err != nil {
			return err
		}
		return s.deleteReferences(tx, id)
	})
	if models.IsNotFoundError(err) {
		return s.missing(ctx, id)
	}
	return conflict(err)
}

func (s Scope) find(ctx context.Context, tx *storage.Connection, id uuid.UUID) (Row, error) {
	sql, args := s.query(tx).Where("id = ?", id).Select("id").ToSQL(pop.NewModel(&Resource{}, ctx))
	rows, err := s.fetch(tx, "scim_resources WHERE id = ("+sql+")", args...)
	if err != nil {
		return Row{}, err
	}
	if len(rows) == 0 {
		return Row{}, NotFound()
	}
	return rows[0], nil
}

func (s Scope) fetch(tx *storage.Connection, from string, args ...any) ([]Row, error) {
	rows := []Row{}
	err := tx.RawQuery("SELECT "+resourceColumns+", "+s.refs+" AS refs FROM "+from, args...).All(&rows)
	return rows, err
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
	rows, err := s.fetch(s.db.WithContext(bounded), fmt.Sprintf("unnest(array(%s LIMIT $%d OFFSET $%d)) WITH ORDINALITY page(id, n) JOIN scim_resources USING (id) ORDER BY page.n", sql, len(values)+1, len(values)+2), append(values, search.Count, search.Offset)...)
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

func (s Scope) missing(ctx context.Context, id uuid.UUID) error {
	found, err := s.query(s.db.WithContext(ctx)).Where("id = ?", id).Exists(&Resource{})
	if err != nil {
		return err
	}
	if !found {
		return NotFound()
	}
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func (s Scope) write(ctx context.Context, links []Link, save func(*storage.Connection) (*Resource, error)) (Row, error) {
	var row Row
	err := s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		saved, err := save(tx)
		if err != nil {
			return err
		}
		for _, link := range links {
			if err := s.link(tx, saved.ID, link); err != nil {
				return err
			}
		}
		row, err = s.find(ctx, tx, saved.ID)
		return err
	})
	return row, err
}

func (s Scope) query(tx *storage.Connection) *pop.Query {
	return tx.Q().
		Where("sso_provider_id = ?", s.providerID).
		Where("resource_type = " + query.QuoteLiteral(s.resourceType)).
		Where("deleted_at IS NULL")
}

func (s Scope) create(tx *storage.Connection, document string) (*Resource, error) {
	resource := &Resource{}
	err := tx.RawQuery(
		"INSERT INTO scim_resources (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING "+resourceColumns,
		uuid.NewV7(), s.providerID, s.resourceType, document,
	).First(resource)
	return resource, err
}

func (s Scope) update(tx *storage.Connection, id uuid.UUID, document string, guard condition) (*Resource, error) {
	resource := &Resource{}
	if err := tx.RawQuery(
		"UPDATE scim_resources SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND "+guard.text+" RETURNING "+resourceColumns,
		append([]any{document, id, s.providerID, s.resourceType}, guard.args...)...,
	).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.SCIMNotFoundError{}
		}
		return nil, err
	}
	return resource, nil
}

func (s Scope) remove(tx *storage.Connection, id uuid.UUID, version string) error {
	count, err := tx.RawQuery(
		"UPDATE scim_resources SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)",
		id, s.providerID, s.resourceType, query.VersionTime(version),
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return models.SCIMNotFoundError{}
	}
	return nil
}

func conflict(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch pg.Code {
	case pgerrcode.UniqueViolation:
		return scimerrors.ErrUniqueness("resource must be unique")
	case pgerrcode.DeadlockDetected:
		return scimerrors.NewError(http.StatusConflict, "", "resource changed during the request; retry")
	}
	return err
}

func guard(document, version string, links []Link) condition {
	current := condition{"updated_at = COALESCE(?, updated_at)", []any{query.VersionTime(version)}}
	if len(links) == 0 || slices.ContainsFunc(links, func(l Link) bool { return l.Only == nil }) {
		return current
	}
	return condition{"(" + current.text + " OR resource = ?::jsonb)", append(current.args, document)}
}
