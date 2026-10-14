package scim

import (
	"context"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/api/scim/store"
	"github.com/supabase/auth/internal/storage"
)

type repository[T core.Resource] struct {
	db           *storage.Connection
	resourceType string
	query        query.Resource
}

func newRepository[T core.Resource](db *storage.Connection, resourceType string, q query.Resource) *repository[T] {
	return &repository[T]{db: db, resourceType: resourceType, query: q}
}

func (r *repository[T]) List(ctx context.Context, request *protocol.SearchRequest) ([]T, int, error) {
	found, err := r.query.Search(request)
	if err != nil {
		return nil, 0, err
	}
	scope, err := r.scope(ctx, r.projected(ctx))
	if err != nil {
		return nil, 0, err
	}
	rows, total, err := scope.Page(ctx, store.Search{
		Search: found,
		Count:  request.Count,
		Offset: request.Offset(),
	})
	if err != nil {
		return nil, 0, err
	}
	items, err := store.Decode[T](rows, r.query.Location())
	return items, total, err
}

func (r *repository[T]) Read(ctx context.Context, id string) (T, error) {
	var zero T
	key, err := uuid.Parse(id)
	if err != nil {
		return zero, store.NotFound()
	}
	scope, err := r.scope(ctx, r.projected(ctx))
	if err != nil {
		return zero, err
	}
	row, err := scope.Find(ctx, key)
	if err != nil {
		return zero, err
	}
	return row.Into[T](r.query.Location())
}

func (r *repository[T]) Create(ctx context.Context, item T) (T, error) {
	return r.save(ctx, item, func(scope store.Scope, document string, links []store.Link) (store.Row, error) {
		return scope.Create(ctx, document, links)
	})
}

func (r *repository[T]) Update(ctx context.Context, item T) (T, error) {
	return r.save(ctx, item, func(scope store.Scope, document string, links []store.Link) (store.Row, error) {
		return scope.Update(ctx, idOf(item), document, item.Common().Meta.Version, links)
	})
}

func (r *repository[T]) Delete(ctx context.Context, item T) error {
	scope, err := r.scope(ctx, "")
	if err != nil {
		return err
	}
	return scope.Delete(ctx, idOf(item), item.Common().Meta.Version)
}

func idOf[T core.Resource](item T) uuid.UUID {
	id, _ := uuid.Parse(item.Common().ID)
	return id
}

func (r *repository[T]) save(ctx context.Context, item T, persist func(store.Scope, string, []store.Link) (store.Row, error)) (T, error) {
	var zero T
	scope, err := r.scope(ctx, r.projected(ctx))
	if err != nil {
		return zero, err
	}
	document, links, err := store.Encode(item, r.query.References())
	if err != nil {
		return zero, err
	}
	row, err := persist(scope, document, links)
	if err != nil {
		return zero, err
	}
	return row.Into[T](r.query.Location())
}

func (r *repository[T]) scope(ctx context.Context, refs string) (store.Scope, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return store.Scope{}, scimerrors.ErrInternal("missing SCIM token")
	}
	return store.NewScope(r.db, token.SSOProviderID, r.resourceType, refs), nil
}

func (r *repository[T]) projected(ctx context.Context) string {
	return r.query.Select(protocol.ProjectionFrom(ctx))
}
