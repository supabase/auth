package store

import (
	"context"
	"database/sql"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const resourceColumns = "id, resource_type, resource, created_at, updated_at"

type Ancestor struct {
	SourceID uuid.UUID `db:"source_id"`
	Longest  int       `db:"longest"`
}

type Scope struct {
	db           *storage.Connection
	providerID   uuid.UUID
	resourceType string
	refs         string
}

func NewScope(db *storage.Connection, provider uuid.UUID, resourceType, refs string) Scope {
	return Scope{db: db, providerID: provider, resourceType: resourceType, refs: refs}
}

func (s Scope) Create(ctx context.Context, document string, links []Link) (Row, error) {
	row, err := s.write(ctx, links, func(tx *storage.Connection) (*Resource, error) {
		return s.create(tx, document)
	})
	return row, conflict(err)
}

func (s Scope) Update(ctx context.Context, id uuid.UUID, document, version string, links []Link) (Row, error) {
	row, err := s.write(ctx, links, func(tx *storage.Connection) (*Resource, error) {
		return s.update(tx, id, document, version)
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

func (s Scope) update(tx *storage.Connection, id uuid.UUID, document, version string) (*Resource, error) {
	resource := &Resource{}
	if err := tx.RawQuery(
		"UPDATE scim_resources SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND (updated_at = COALESCE(?, updated_at) OR resource = ?::jsonb) RETURNING "+resourceColumns,
		document, id, s.providerID, s.resourceType, query.VersionTime(version), document,
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

func (s Scope) addReferences(tx *storage.Connection, source uuid.UUID, attribute string, types []string, targets []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return added, nil
	}
	err := tx.RawQuery(
		"INSERT INTO scim_resource_references (sso_provider_id, source_id, attribute, target_id, target_type) SELECT sso_provider_id, ?, ?, id, resource_type FROM scim_resources WHERE sso_provider_id = ? AND resource_type = any(?::text[]) AND deleted_at IS NULL AND id = any(?::uuid[]) RETURNING target_id",
		source, attribute, s.providerID, types, uuidStrings(targets),
	).All(&added)
	return added, errors.Wrap(err, "error adding SCIM references")
}

func (s Scope) removeReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		"DELETE FROM scim_resource_references WHERE source_id = ? AND attribute = ? AND target_id = any(?::uuid[])",
		source, attribute, uuidStrings(targets),
	).Exec(), "error removing SCIM references")
}

func (s Scope) findTargets(tx *storage.Connection, source uuid.UUID, attribute string, only []string) ([]uuid.UUID, error) {
	targets := []uuid.UUID{}
	q := tx.RawQuery("SELECT target_id FROM scim_resource_references WHERE source_id = ? AND attribute = ?", source, attribute)
	if only != nil {
		q = tx.RawQuery("SELECT target_id FROM scim_resource_references WHERE source_id = ? AND attribute = ? AND target_id = any(?::uuid[])", source, attribute, only)
	}
	err := q.All(&targets)
	return targets, errors.Wrap(err, "error finding SCIM targets")
}

func (s Scope) findAncestors(tx *storage.Connection, target uuid.UUID, attribute string) ([]Ancestor, error) {
	ancestors := []Ancestor{}
	err := tx.RawQuery(
		`WITH RECURSIVE chain (source_id, depth) AS (
			SELECT source_id, 1 FROM scim_resource_references WHERE target_id = ? AND attribute = ?
			UNION
			SELECT r.source_id, c.depth + 1 FROM chain c JOIN scim_resource_references r ON r.target_id = c.source_id AND r.attribute = ? WHERE c.depth < ?
		)
		SELECT source_id, max(depth) AS longest FROM chain GROUP BY source_id`,
		target, attribute, attribute, query.MaxDepth,
	).All(&ancestors)
	return ancestors, errors.Wrap(err, "error finding SCIM ancestors")
}

func (s Scope) depth(tx *storage.Connection, ids []uuid.UUID, attribute string) (int, error) {
	var walk struct {
		Depth int `db:"depth"`
	}
	err := tx.RawQuery(
		`WITH RECURSIVE walk (id, depth) AS (
			SELECT id, 1 FROM scim_resources WHERE id = any(?::uuid[]) AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL
			UNION
			SELECT t.id, w.depth + 1 FROM walk w JOIN scim_resource_references r ON r.source_id = w.id AND r.attribute = ? JOIN scim_resources t ON t.id = r.target_id AND t.resource_type = ? AND t.deleted_at IS NULL WHERE w.depth <= ?
		)
		SELECT coalesce(max(depth), 0) AS depth FROM walk`,
		uuidStrings(ids), s.providerID, s.resourceType, attribute, s.resourceType, query.MaxDepth,
	).First(&walk)
	return walk.Depth, errors.Wrap(err, "error finding SCIM depth")
}

func (s Scope) deleteReferences(tx *storage.Connection, id uuid.UUID) error {
	err := tx.RawQuery("DELETE FROM scim_resource_references WHERE source_id = ? OR target_id = ?", id, id).Exec()
	return errors.Wrap(err, "error deleting SCIM references")
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
