package store

import (
	"context"
	"slices"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const insertResource = `
INSERT INTO scim_resources (id, sso_provider_id, resource_type, resource, lower_name)
VALUES (?, ?, ?, ?::jsonb, ?)`

const stampsReturned = `
RETURNING created_at, updated_at`

const updateResource = `
UPDATE scim_resources
SET resource = ?::jsonb, lower_name = ?, updated_at = now()
WHERE id = ?
  AND ` + scopeWhere + `
  AND updated_at = COALESCE(?, updated_at)`

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

func (sc scope) create(tx *storage.Connection, id uuid.UUID, body []byte, name any) error {
	return tx.RawQuery(
		insertResource,
		id, sc.providerID, sc.Type, string(body), name,
	).Exec()
}

func (sc scope) update(tx *storage.Connection, id uuid.UUID, body []byte, name any, version string) error {
	count, err := tx.RawQuery(
		updateResource,
		string(body), name, id, sc.providerID, sc.Type, versionTime(version),
	).ExecWithCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNoMatch
	}
	return nil
}
