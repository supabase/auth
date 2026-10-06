package scim

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/api/scim/ref"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type repository[T core.Resource] struct {
	db           *storage.Connection
	resourceType string
	locations    map[string]string
	schemas      core.Schemas
	references   []ref.Reference
}

func NewRepository[T core.Resource](db *storage.Connection, resourceType string, locations map[string]string, schemas core.Schemas, references ...ref.Reference) server.Repository[T] {
	for i, reference := range references {
		references[i] = reference.Resolve(schemas)
	}
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
	tx := r.db.WithContext(ctx)
	q, err := r.filter(tx, scope, query.Filter)
	if err != nil {
		return nil, 0, err
	}
	if query.Count == 0 {
		total, err := q.Count(&models.SCIMResource{})
		return []T{}, total, err
	}
	rows, err := r.page(tx, scope, q, query)
	if err != nil {
		return nil, 0, err
	}
	items, err := r.decodeAll(tx, scope, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return items, q.Paginator.TotalEntriesSize, nil
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.FromString(id)
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
	return r.decodeOne(tx, scope, row)
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
	saved, err := r.save(ctx, scope, targets, func(tx *storage.Connection) (*models.SCIMResource, error) {
		return scope.Update(tx, uuid.FromStringOrNil(common.ID), document, common.Meta.Version)
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
	id := uuid.FromStringOrNil(common.ID)
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
		return "created_at, id", nil, nil
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
	if column, ok := query.Columns[strings.Join(keys, ".")]; ok {
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
	if len(keys) == 1 {
		return `lower(resource ->> ` + models.QuoteLiteral(keys[0]) + `) COLLATE "C"` + direction + ", id", nil, nil
	}
	return `lower(resource #>> ?::text[]) COLLATE "C"` + direction + ", id", []any{textArray(keys)}, nil
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
		saved, err = r.decodeOne(tx, scope, row)
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

func (r *repository[T]) filter(tx *storage.Connection, scope models.SCIMScope, expression string) (*pop.Query, error) {
	q := scope.Query(tx)
	if expression == "" {
		return q, nil
	}
	builder, err := protocol.Filter(r.schemas, expression, query.NewEvaluator(r.schemas, r.attributes()...))
	if err != nil {
		return nil, err
	}
	return builder.Build(q), nil
}

func (r *repository[T]) page(tx *storage.Connection, scope models.SCIMScope, q *pop.Query, query *protocol.SearchRequest) ([]models.SCIMResource, error) {
	order, args, err := r.order(query)
	if err != nil {
		return nil, err
	}
	q.Paginator = &pop.Paginator{PerPage: query.Count, Offset: query.Offset()}
	keys := []models.SCIMResource{}
	if err := q.Select("id").Order(order, args...).All(&keys); err != nil || len(keys) == 0 {
		return keys, err
	}
	ids := make([]string, len(keys))
	for i, key := range keys {
		ids[i] = key.ID.String()
	}
	rows := []models.SCIMResource{}
	return rows, scope.Query(tx).Where("id = any(?::uuid[])", ids).Order(order, args...).All(&rows)
}

func (r *repository[T]) attributes() []query.Reference {
	references := make([]query.Reference, len(r.references))
	for i, reference := range r.references {
		references[i] = reference
	}
	return references
}

func (r *repository[T]) decodeOne(tx *storage.Connection, scope models.SCIMScope, row *models.SCIMResource) (T, error) {
	items, err := r.decodeAll(tx, scope, []models.SCIMResource{*row}, protocol.Projection{})
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
	if _, ok := errors.AsType[models.SCIMUniquenessError](err); ok {
		return scimerrors.ErrUniqueness("resource must be unique")
	}
	return err
}

func notFound() error {
	return scimerrors.ErrNotFound("Not found")
}

func textArray(keys []string) string {
	quoted := make([]string, len(keys))
	for i, key := range keys {
		quoted[i] = strconv.Quote(key)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}
