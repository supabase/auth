package scim

import (
	"context"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/api/scim/store"
	"github.com/supabase/auth/internal/storage"
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

func (r *repository[T]) List(ctx context.Context, request *protocol.SearchRequest) ([]T, int, error) {
	scope, err := r.scope(ctx)
	if err != nil {
		return nil, 0, err
	}
	clause, err := query.Where(r.schemas, scope.ProviderID, r.endpoint(), r.references, request.Filter)
	if err != nil {
		return nil, 0, err
	}
	if prefix, ok := clause.(query.Prefix); ok && request.SortBy == "" {
		sorted := *request
		sorted.SortBy = prefix.Attribute
		request = &sorted
	}
	order, args, err := query.Order(r.schemas, request)
	if err != nil {
		return nil, 0, err
	}
	rows, total, err := scope.Page(ctx, store.Search{
		Where:     clause,
		Order:     order,
		OrderArgs: args,
		Count:     request.Count,
		Offset:    request.Offset(),
		Refs:      r.refs(ctx),
	})
	if err != nil {
		return nil, 0, err
	}
	items, err := store.Decode[T](rows, r.endpoint())
	return items, total, err
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.Parse(id)
	if err != nil {
		return zero, store.NotFound()
	}
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	row, err := scope.Find(ctx, key, r.refs(ctx))
	if err != nil {
		return zero, err
	}
	return row.Into[T](r.endpoint())
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	return r.save(ctx, item, func(scope store.Scope, document string, links []store.Link, refs string) (store.Row, error) {
		return scope.Create(ctx, document, links, refs)
	})
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	common := item.Common()
	id, _ := uuid.Parse(common.ID)
	return r.save(ctx, item, func(scope store.Scope, document string, links []store.Link, refs string) (store.Row, error) {
		return scope.Update(ctx, id, document, common.Meta.Version, links, refs)
	})
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	scope, err := r.scope(ctx)
	if err != nil {
		return err
	}
	common := item.Common()
	id, _ := uuid.Parse(common.ID)
	return scope.Delete(ctx, id, common.Meta.Version)
}

func (r *repository[T]) save(ctx context.Context, item T, write func(store.Scope, string, []store.Link, string) (store.Row, error)) (T, error) {
	var zero T
	scope, err := r.scope(ctx)
	if err != nil {
		return zero, err
	}
	document, links, err := store.Encode(item, r.references)
	if err != nil {
		return zero, err
	}
	row, err := write(scope, document, links, r.refs(ctx))
	if err != nil {
		return zero, err
	}
	return row.Into[T](r.endpoint())
}

func (r *repository[T]) scope(ctx context.Context) (store.Scope, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return store.Scope{}, scimerrors.ErrInternal("missing SCIM token")
	}
	return store.NewScope(r.db, token.SSOProviderID, r.resourceType), nil
}

func (r *repository[T]) refs(ctx context.Context) string {
	return query.Select(r.references, protocol.ProjectionFrom(ctx), r.locations)
}

func (r *repository[T]) endpoint() string {
	return r.locations[r.resourceType]
}
