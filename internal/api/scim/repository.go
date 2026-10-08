package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	var items []T
	var total int
	err = r.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := tx.RawQuery("SET LOCAL statement_timeout = '5s'").Exec(); err != nil {
			return err
		}
		items, total, err = r.list(ctx, tx, scope, query)
		return err
	})
	if models.IsQueryCanceledError(err) {
		return nil, 0, scimerrors.ErrTooMany("the query took too long")
	}
	return items, total, err
}

func (r *repository[T]) list(ctx context.Context, tx *storage.Connection, scope models.SCIMScope, request *protocol.SearchRequest) ([]T, int, error) {
	q, clause, err := r.filter(tx, scope, request.Filter)
	if err != nil {
		return nil, 0, err
	}
	if prefix, ok := clause.(query.Prefix); ok && request.SortBy == "" {
		sorted := *request
		sorted.SortBy = prefix.Attribute
		request = &sorted
	}
	if request.Count == 0 {
		total, err := q.Count(&models.SCIMResource{})
		return []T{}, total, err
	}
	rows, total, err := r.page(ctx, tx, scope, q, request)
	if err != nil {
		return nil, 0, err
	}
	items, err := r.decodeAll(tx, scope, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
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
	tx := r.db.WithContext(ctx)
	row, err := scope.Find(tx, key)
	if models.IsNotFoundError(err) {
		return zero, notFound()
	}
	if err != nil {
		return zero, err
	}
	return r.decodeOne(tx, scope, row, protocol.ProjectionFrom(ctx))
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
	if err != nil {
		return zero, invalid(err)
	}
	return saved, nil
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
		return zero, r.missing(ctx, common.ID)
	}
	if err != nil {
		return zero, invalid(err)
	}
	return saved, nil
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
		return r.missing(ctx, common.ID)
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

func (r *repository[T]) missing(ctx context.Context, id string) error {
	if _, err := r.Read(ctx, id); err != nil {
		return err
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
		saved, err = r.decodeOne(tx, scope, row, protocol.Projection{})
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

func (r *repository[T]) filter(tx *storage.Connection, scope models.SCIMScope, expression string) (*pop.Query, query.Clause, error) {
	q := scope.Query(tx)
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

func (r *repository[T]) page(ctx context.Context, tx *storage.Connection, scope models.SCIMScope, q *pop.Query, query *protocol.SearchRequest) ([]models.SCIMResource, int, error) {
	order, args, err := r.order(query)
	if err != nil {
		return nil, 0, err
	}
	keys := []models.SCIMResource{}
	sql, values := q.Select("id").Order(order, args...).ToSQL(pop.NewModel(&keys, ctx))
	if err := tx.RawQuery(fmt.Sprintf("%s LIMIT %d OFFSET %d", sql, query.Count, query.Offset()), values...).All(&keys); err != nil {
		return nil, 0, err
	}
	total := query.Offset() + len(keys)
	if len(keys) == query.Count || (len(keys) == 0 && query.Offset() > 0) {
		if total, err = q.Count(&models.SCIMResource{}); err != nil {
			return nil, 0, err
		}
	}
	if len(keys) == 0 {
		return keys, total, nil
	}
	ids := make([]string, len(keys))
	for i, key := range keys {
		ids[i] = key.ID.String()
	}
	rows := []models.SCIMResource{}
	return rows, total, scope.Query(tx).Where("id = any(?::uuid[])", ids).Order(order, args...).All(&rows)
}

func (r *repository[T]) decodeOne(tx *storage.Connection, scope models.SCIMScope, row *models.SCIMResource, projection protocol.Projection) (T, error) {
	items, err := r.decodeAll(tx, scope, []models.SCIMResource{*row}, projection)
	if err != nil {
		var zero T
		return zero, err
	}
	return items[0], nil
}

func (r *repository[T]) decodeAll(tx *storage.Connection, scope models.SCIMScope, rows []models.SCIMResource, projection protocol.Projection) ([]T, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	elements := map[uuid.UUID]map[string]any{}
	for _, reference := range r.references {
		if !projection.Returns(reference.Name()) {
			continue
		}
		loaded, err := reference.Load(tx, scope, ids, r.locations)
		if err != nil {
			return nil, err
		}
		for id, list := range loaded {
			if elements[id] == nil {
				elements[id] = map[string]any{}
			}
			elements[id][reference.Name()] = list
		}
	}
	items := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := r.decode(&row, elements[row.ID])
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *repository[T]) decode(row *models.SCIMResource, attributes map[string]any) (T, error) {
	item, err := row.As[T](r.locations[r.resourceType])
	if err != nil {
		return item, err
	}
	if len(attributes) > 0 {
		raw, err := json.Marshal(attributes)
		if err != nil {
			return item, err
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return item, err
		}
	}
	return item, nil
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
