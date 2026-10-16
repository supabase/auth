package store

import (
	"context"
	"slices"
	"uuid"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
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

func (s *Store) Create(ctx context.Context, doc store.Document) (store.Record, error) {
	if !slices.ContainsFunc(doc.Links, func(l store.Link) bool { return len(l.Targets) > 0 }) {
		return s.insert(ctx, doc)
	}
	return s.write(ctx, doc, func(sc scope, tx *storage.Connection, id uuid.UUID, name any) error {
		if err := sc.create(tx, id, doc.Body, name); err != nil {
			return err
		}
		return sc.attach(tx, id, doc.Links)
	})
}

func (s *Store) Update(ctx context.Context, doc store.Document, version string) (store.Record, error) {
	return s.write(ctx, doc, func(sc scope, tx *storage.Connection, id uuid.UUID, name any) error {
		if err := sc.update(tx, id, doc.Body, name, version); err != nil {
			return err
		}
		return sc.relink(tx, id, doc.Links)
	})
}

func (s *Store) Delete(ctx context.Context, id, version string) error {
	sc, key, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	return conflict(s.db.conn.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return sc.remove(tx, key, version)
	}))
}

func (s *Store) insert(ctx context.Context, doc store.Document) (store.Record, error) {
	sc, id, name, err := s.prepare(ctx, doc)
	if err != nil {
		return store.Record{}, err
	}
	m := model{ID: id, Resource: doc.Body}
	err = s.db.conn.WithContext(ctx).RawQuery(
		insertResource+stampsReturned,
		id, sc.providerID, sc.Type, string(doc.Body), name,
	).First(&m)
	return m.record(), conflict(err)
}

func (s *Store) target(ctx context.Context, id string) (scope, uuid.UUID, error) {
	sc, err := s.scope(ctx)
	if err != nil {
		return sc, uuid.UUID{}, err
	}
	key, err := uuid.Parse(id)
	if err != nil {
		return sc, key, store.ErrNoMatch
	}
	return sc, key, nil
}

func (s *Store) prepare(ctx context.Context, doc store.Document) (scope, uuid.UUID, any, error) {
	sc, id, err := s.target(ctx, doc.ID)
	if err != nil {
		return sc, id, nil, err
	}
	name, err := sc.LowerName(doc.Body)
	return sc, id, name, err
}

func (s *Store) write(ctx context.Context, doc store.Document, save func(scope, *storage.Connection, uuid.UUID, any) error) (store.Record, error) {
	sc, id, name, err := s.prepare(ctx, doc)
	if err != nil {
		return store.Record{}, err
	}
	var record store.Record
	err = s.db.conn.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := save(sc, tx, id, name); err != nil {
			return err
		}
		record, err = sc.find(tx, id, doc.References)
		return err
	})
	return record, conflict(err)
}

func (s *Store) scope(ctx context.Context) (scope, error) {
	provider, err := s.db.tenant(ctx)
	return scope{Store: s, providerID: provider}, err
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
		return scimerrors.ErrChanged()
	}
	return err
}
