package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const queryTimeout = 5 * time.Second

type repository[T core.Resource] struct {
	db           *storage.Connection
	resourceType string
	locations    map[string]string
	schemas      core.Schemas
	references   []query.Reference
}

func NewRepository[T core.Resource](db *storage.Connection, resourceType string, locations map[string]string, schemas core.Schemas, references ...query.Reference) server.Repository[T] {
	return &repository[T]{
		db:           db,
		resourceType: resourceType,
		locations:    locations,
		schemas:      schemas,
		references:   references,
	}
}

func (r *repository[T]) List(ctx context.Context, query *protocol.SearchRequest) ([]T, int, error) {
	scope, err := r.scope(ctx)
	if err != nil {
		return nil, 0, err
	}
	items, total, err := r.list(ctx, scope, query)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, 0, scimerrors.ErrTooMany("the query took too long")
	}
	return items, total, err
}

func (r *repository[T]) list(ctx context.Context, scope models.SCIMScope, request *protocol.SearchRequest) ([]T, int, error) {
	q, clause, err := r.filter(scope, request.Filter)
	if err != nil {
		return nil, 0, err
	}
	if prefix, ok := clause.(query.Prefix); ok && request.SortBy == "" {
		sorted := *request
		sorted.SortBy = prefix.Attribute
		request = &sorted
	}
	if request.Count == 0 {
		total, err := r.count(ctx, q)
		return []T{}, total, err
	}
	return r.page(ctx, q, request)
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.Parse(id)
	if err != nil {
		return zero, notFound()
	}
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	return r.find(ctx, r.db.WithContext(ctx), scope, key, protocol.ProjectionFrom(ctx))
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	var zero T
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	document, targets, err := r.encode(item)
	if err != nil {
		return zero, err
	}
	saved, err := r.save(ctx, scope, targets, func(tx *storage.Connection) (*models.SCIMResource, error) {
		return scope.Create(tx, document)
	})
	return saved, invalid(err)
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	var zero T
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	document, targets, err := r.encode(item)
	if err != nil {
		return zero, err
	}
	common := item.Common()
	id, _ := uuid.Parse(common.ID)
	saved, err := r.save(ctx, scope, targets, func(tx *storage.Connection) (*models.SCIMResource, error) {
		return scope.Update(tx, id, document, common.Meta.Version)
	})
	if models.IsNotFoundError(err) {
		return zero, r.missing(ctx, scope, id)
	}
	return saved, invalid(err)
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	scope, err := r.scope(ctx)
	if err != nil {
		return err
	}
	common := item.Common()
	id, _ := uuid.Parse(common.ID)
	err = r.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := scope.Delete(tx, id, common.Meta.Version); err != nil {
			return err
		}
		return scope.DeleteReferences(tx, id)
	})
	if models.IsNotFoundError(err) {
		return r.missing(ctx, scope, id)
	}
	return err
}

func (r *repository[T]) scope(ctx context.Context) (models.SCIMScope, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return models.SCIMScope{}, scimerrors.ErrInternal("missing SCIM token")
	}
	return models.SCIMScope{ProviderID: token.SSOProviderID, ResourceType: r.resourceType}, nil
}

func (r *repository[T]) missing(ctx context.Context, scope models.SCIMScope, id uuid.UUID) error {
	found, err := scope.Query(r.db.WithContext(ctx)).Where("id = ?", id).Exists(&models.SCIMResource{})
	if err != nil {
		return err
	}
	if !found {
		return notFound()
	}
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func (r *repository[T]) order(request *protocol.SearchRequest) (string, []any, error) {
	if request.SortBy == "" {
		return "id", nil, nil
	}
	parent, attribute, err := request.SortAttribute(r.schemas)
	if err != nil {
		return "", nil, err
	}
	direction := " ASC"
	if request.Descending() {
		direction = " DESC"
	}
	keys := []string{parent.Name}
	if parent != attribute {
		keys = append(keys, attribute.Name)
	}
	path := strings.Join(keys, ".")
	if path == "meta.created" {
		return "id" + direction, nil, nil
	}
	if column, ok := query.Columns[path]; ok {
		return column + direction + ", id", nil, nil
	}
	if parent.MultiValued {
		keys = []string{parent.Name, "0", attribute.Name}
	}
	for _, extension := range r.schemas.Extensions() {
		if extension.Attributes.Lookup(parent.Name) == parent {
			keys = append([]string{string(extension.ID)}, keys...)
		}
	}
	value, args := `resource #>> ?::text[]`, []any{keys}
	if len(keys) == 1 {
		value, args = `resource ->> `+models.QuoteLiteral(keys[0]), nil
	}
	if parent.MultiValued {
		value, args = `coalesce(jsonb_path_query_first(resource, ?::jsonpath) #>> '{}', `+value+`)`, []any{primary(keys), keys}
	}
	if !attribute.CaseExact {
		value = "lower(" + value + ")"
	}
	return value + ` COLLATE "C"` + direction + ", id", args, nil
}

func (r *repository[T]) save(ctx context.Context, scope models.SCIMScope, targets map[string][]uuid.UUID, write func(*storage.Connection) (*models.SCIMResource, error)) (T, error) {
	var saved T
	err := r.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := write(tx)
		if err != nil {
			return err
		}
		if err := r.link(tx, scope, row.ID, targets); err != nil {
			return err
		}
		saved, err = r.find(ctx, tx, scope, row.ID, protocol.ProjectionFrom(ctx))
		return err
	})
	return saved, err
}

func (r *repository[T]) link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets map[string][]uuid.UUID) error {
	for _, reference := range r.references {
		if err := reference.Link(tx, scope, source, targets[reference.Name()]); err != nil {
			return err
		}
	}
	return nil
}

func (r *repository[T]) filter(scope models.SCIMScope, expression string) (*pop.Query, query.Clause, error) {
	q := scope.Query(r.db)
	if expression == "" {
		return q, nil, nil
	}
	clause, err := protocol.Filter(r.schemas, expression, query.NewEvaluator(r.schemas, scope.ProviderID, r.locations[r.resourceType], r.references...))
	if err != nil {
		return nil, nil, err
	}
	text, args := clause.SQL()
	return q.Where(text, args...), clause, nil
}

func (r *repository[T]) page(ctx context.Context, q *pop.Query, query *protocol.SearchRequest) ([]T, int, error) {
	order, args, err := r.order(query)
	if err != nil {
		return nil, 0, err
	}
	sql, values := q.Select("id").Order(order, args...).ToSQL(pop.NewModel(&models.SCIMResource{}, ctx))
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	items, err := r.fetch(r.db.WithContext(bounded), protocol.ProjectionFrom(ctx), fmt.Sprintf("unnest(array(%s LIMIT $%d OFFSET $%d)) WITH ORDINALITY page(id, n) JOIN scim_resources USING (id) ORDER BY page.n", sql, len(values)+1, len(values)+2), append(values, query.Count, query.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	total := query.Offset() + len(items)
	if len(items) == query.Count || (len(items) == 0 && query.Offset() > 0) {
		total, err = r.count(ctx, q)
	}
	return items, total, err
}

func (r *repository[T]) count(ctx context.Context, q *pop.Query) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	bounded := *q
	bounded.Connection = q.Connection.WithContext(ctx)
	return bounded.Count(&models.SCIMResource{})
}

func (r *repository[T]) find(ctx context.Context, tx *storage.Connection, scope models.SCIMScope, id uuid.UUID, projection protocol.Projection) (T, error) {
	var zero T
	sql, args := scope.Query(tx).Where("id = ?", id).Select("id").ToSQL(pop.NewModel(&models.SCIMResource{}, ctx))
	items, err := r.fetch(tx, projection, "scim_resources WHERE id = ("+sql+")", args...)
	if err != nil {
		return zero, err
	}
	if len(items) == 0 {
		return zero, notFound()
	}
	return items[0], nil
}

type record struct {
	models.SCIMResource
	References json.RawMessage `db:"refs"`
}

func (r *repository[T]) fetch(tx *storage.Connection, projection protocol.Projection, from string, args ...any) ([]T, error) {
	rows := []record{}
	if err := tx.RawQuery(fmt.Sprintf("SELECT %s, %s AS refs FROM %s", models.SCIMResourceColumns, r.selects(projection), from), args...).All(&rows); err != nil {
		return nil, err
	}
	items := make([]T, len(rows))
	for i, row := range rows {
		item, err := row.As[T](r.locations[r.resourceType])
		if err == nil {
			err = json.Unmarshal(row.References, &item)
		}
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

func (r *repository[T]) selects(projection protocol.Projection) string {
	pairs := []string{}
	for _, reference := range r.references {
		if projection.Returns(reference.Name()) {
			pairs = append(pairs, models.QuoteLiteral(reference.Name()), reference.Select(r.locations))
		}
	}
	if len(pairs) == 0 {
		return "'{}'::json"
	}
	return "json_build_object(" + strings.Join(pairs, ", ") + ")"
}

func (r *repository[T]) encode(item T) (string, map[string][]uuid.UUID, error) {
	document, err := core.NewObject(item)
	if err != nil {
		return "", nil, err
	}
	for _, key := range []string{"id", "meta", "password"} {
		document.Remove(key)
	}
	targets := map[string][]uuid.UUID{}
	for _, reference := range r.references {
		if targets[reference.Name()], err = reference.Extract(document.Get(reference.Name())); err != nil {
			return "", nil, err
		}
		document.Remove(reference.Name())
	}
	raw, err := json.Marshal(document)
	return string(raw), targets, err
}

func invalid(err error) error {
	if pg := utilities.NewPostgresError(err); pg != nil && pg.IsUniqueConstraintViolated() {
		return scimerrors.ErrUniqueness("resource must be unique")
	}
	return err
}

func primary(keys []string) string {
	quoted := make([]string, len(keys))
	for i, key := range keys {
		quoted[i] = query.Quote(key)
	}
	return "$." + strings.Join(quoted[:len(keys)-2], ".") + "[*] ? (@.primary == true)." + quoted[len(keys)-1]
}

func notFound() error {
	return scimerrors.ErrNotFound("Not found")
}
