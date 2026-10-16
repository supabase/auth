package store

import (
	"context"
	"slices"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const insertResource = `
INSERT INTO scim_resources (id, sso_provider_id, resource_type, resource)
VALUES (?, ?, ?, ?::jsonb)`

const stampsReturned = `
RETURNING created_at, updated_at`

const updateResource = `
UPDATE scim_resources
SET resource = ?::jsonb, updated_at = now()
WHERE id = ?
  AND ` + scopeWhere + `
  AND updated_at = COALESCE(?, updated_at)`

func (s *Store) Create(ctx context.Context, doc store.Document) (store.Record, error) {
	if !slices.ContainsFunc(doc.Links, func(l store.Link) bool { return len(l.Targets) > 0 }) {
		return s.insert(ctx, doc)
	}
	return s.write(ctx, doc, true, func(sc scope, tx *storage.Connection, id uuid.UUID) error {
		return sc.create(tx, id, doc.Body)
	})
}

func (s *Store) Update(ctx context.Context, doc store.Document, version string) (store.Record, error) {
	return s.write(ctx, doc, false, func(sc scope, tx *storage.Connection, id uuid.UUID) error {
		return sc.update(tx, id, doc.Body, version)
	})
}

func (s *Store) insert(ctx context.Context, doc store.Document) (store.Record, error) {
	sc, id, err := s.target(ctx, doc)
	if err != nil {
		return store.Record{}, err
	}
	m := model{ID: id, Resource: doc.Body}
	err = s.db.conn.WithContext(ctx).RawQuery(
		insertResource+stampsReturned,
		id, sc.providerID, sc.Type, string(doc.Body),
	).First(&m)
	return m.record(), conflict(err)
}

func (s *Store) target(ctx context.Context, doc store.Document) (scope, uuid.UUID, error) {
	sc, err := s.scope(ctx)
	if err != nil {
		return sc, uuid.UUID{}, err
	}
	id, err := uuid.Parse(doc.ID)
	if err != nil {
		return sc, id, store.ErrNoMatch
	}
	return sc, id, nil
}

func (s *Store) write(ctx context.Context, doc store.Document, fresh bool, save func(scope, *storage.Connection, uuid.UUID) error) (store.Record, error) {
	sc, id, err := s.target(ctx, doc)
	if err != nil {
		return store.Record{}, err
	}
	sc.fresh = fresh
	var record store.Record
	err = s.db.conn.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := save(sc, tx, id); err != nil {
			return err
		}
		if err := sc.relink(tx, id, doc.Links); err != nil {
			return err
		}
		record, err = sc.find(tx, id, doc.References)
		return err
	})
	return record, conflict(err)
}

func (sc scope) create(tx *storage.Connection, id uuid.UUID, body []byte) error {
	return tx.RawQuery(
		insertResource,
		id, sc.providerID, sc.Type, string(body),
	).Exec()
}

func (sc scope) update(tx *storage.Connection, id uuid.UUID, body []byte, version string) error {
	count, err := tx.RawQuery(
		updateResource,
		string(body), id, sc.providerID, sc.Type, versionTime(version),
	).ExecWithCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNoMatch
	}
	return nil
}
