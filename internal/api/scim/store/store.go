package store

import (
	"context"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

type Store struct {
	db *DB
	query.Resource
}

type scope struct {
	*Store
	providerID uuid.UUID
	fresh      bool
}

func (s *Store) Find(ctx context.Context, id string, refs []store.Reference) (store.Record, error) {
	sc, err := s.scope(ctx)
	if err != nil {
		return store.Record{}, err
	}
	key, err := uuid.Parse(id)
	if err != nil {
		return store.Record{}, notFound()
	}
	return sc.find(s.db.conn.WithContext(ctx), key, refs)
}

func (s *Store) List(ctx context.Context, request *protocol.SearchRequest, refs []store.Reference) ([]store.Record, int, error) {
	sc, err := s.scope(ctx)
	if err != nil {
		return nil, 0, err
	}
	records, total, err := sc.page(ctx, request, refs)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, 0, scimerrors.ErrTooMany("the query took too long")
	}
	return records, total, err
}

func (s *Store) Delete(ctx context.Context, id, version string) error {
	sc, err := s.scope(ctx)
	if err != nil {
		return err
	}
	key, err := uuid.Parse(id)
	if err != nil {
		return store.ErrNoMatch
	}
	return conflict(s.db.conn.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return sc.remove(tx, key, version)
	}))
}

func (s *Store) scope(ctx context.Context) (scope, error) {
	provider, err := s.db.tenant(ctx)
	return scope{Store: s, providerID: provider}, err
}
