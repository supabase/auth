package store

import (
	"context"
	"database/sql"
	"fmt"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const ResourceColumns = "id, sso_provider_id, resource_type, resource, created_at, updated_at, deleted_at"

type Ancestor struct {
	SourceID uuid.UUID `db:"source_id"`
	Longest  int       `db:"longest"`
}

const scimReferences = "scim_resource_references"

type Scope struct {
	db           *storage.Connection
	ProviderID   uuid.UUID
	ResourceType string
}

func NewScope(db *storage.Connection, provider uuid.UUID, resourceType string) Scope {
	return Scope{db: db, ProviderID: provider, ResourceType: resourceType}
}

func (s Scope) Create(ctx context.Context, document string, links []Link, refs string) (Row, error) {
	row, err := s.write(ctx, links, refs, func(tx *storage.Connection) (*Resource, error) {
		return s.create(tx, document)
	})
	return row, unique(err)
}

func (s Scope) Update(ctx context.Context, id uuid.UUID, document, version string, links []Link, refs string) (Row, error) {
	row, err := s.write(ctx, links, refs, func(tx *storage.Connection) (*Resource, error) {
		return s.update(tx, id, document, version)
	})
	if models.IsNotFoundError(err) {
		return row, s.Missing(ctx, id)
	}
	return row, unique(err)
}

func (s Scope) Delete(ctx context.Context, id uuid.UUID, version string) error {
	err := s.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		if err := s.remove(tx, id, version); err != nil {
			return err
		}
		return s.deleteReferences(tx, id)
	})
	if models.IsNotFoundError(err) {
		return s.Missing(ctx, id)
	}
	return err
}

func (s Scope) Missing(ctx context.Context, id uuid.UUID) error {
	found, err := s.query(s.db.WithContext(ctx)).Where("id = ?", id).Exists(&Resource{})
	if err != nil {
		return err
	}
	if !found {
		return NotFound()
	}
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func (s Scope) write(ctx context.Context, links []Link, refs string, save func(*storage.Connection) (*Resource, error)) (Row, error) {
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
		row, err = s.find(ctx, tx, saved.ID, refs)
		return err
	})
	return row, err
}

func (s Scope) query(tx *storage.Connection) *pop.Query {
	return tx.Q().
		Where("sso_provider_id = ?", s.ProviderID).
		Where("resource_type = " + query.QuoteLiteral(s.ResourceType)).
		Where("deleted_at IS NULL")
}

func (s Scope) create(tx *storage.Connection, document string) (*Resource, error) {
	resource := &Resource{}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING %s", resource.TableName(), ResourceColumns),
		uuid.NewV7(), s.ProviderID, s.ResourceType, document,
	).First(resource)
	return resource, err
}

func (s Scope) update(tx *storage.Connection, id uuid.UUID, document, version string) (*Resource, error) {
	resource := &Resource{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at) RETURNING %s", resource.TableName(), ResourceColumns),
		document, id, s.ProviderID, s.ResourceType, query.VersionTime(version),
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
		fmt.Sprintf("UPDATE %q SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)", Resource{}.TableName()),
		id, s.ProviderID, s.ResourceType, query.VersionTime(version),
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
		fmt.Sprintf("INSERT INTO %q (sso_provider_id, source_id, attribute, target_id, target_type) SELECT sso_provider_id, ?, ?, id, resource_type FROM %q WHERE sso_provider_id = ? AND resource_type = any(?::text[]) AND deleted_at IS NULL AND id = any(?::uuid[]) RETURNING target_id", scimReferences, Resource{}.TableName()),
		source, attribute, s.ProviderID, types, uuidStrings(targets),
	).All(&added)
	return added, errors.Wrap(err, "error adding SCIM references")
}

func (s Scope) removeReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE source_id = ? AND attribute = ? AND target_id = any(?::uuid[])", scimReferences),
		source, attribute, uuidStrings(targets),
	).Exec(), "error removing SCIM references")
}

func (s Scope) findTargets(tx *storage.Connection, source uuid.UUID, attribute string) ([]uuid.UUID, error) {
	targets := []uuid.UUID{}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT target_id FROM %q WHERE source_id = ? AND attribute = ?", scimReferences),
		source, attribute,
	).All(&targets)
	return targets, errors.Wrap(err, "error finding SCIM targets")
}

func (s Scope) findAncestors(tx *storage.Connection, target uuid.UUID, attribute string) ([]Ancestor, error) {
	ancestors := []Ancestor{}
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE chain (source_id, depth) AS (
			SELECT source_id, 1 FROM %[1]q WHERE target_id = ? AND attribute = ?
			UNION
			SELECT r.source_id, c.depth + 1 FROM chain c JOIN %[1]q r ON r.target_id = c.source_id AND r.attribute = ? WHERE c.depth < ?
		)
		SELECT source_id, max(depth) AS longest FROM chain GROUP BY source_id`, scimReferences),
		target, attribute, attribute, query.MaxDepth,
	).All(&ancestors)
	return ancestors, errors.Wrap(err, "error finding SCIM ancestors")
}

func (s Scope) depth(tx *storage.Connection, ids []uuid.UUID, attribute string) (int, error) {
	var walk struct {
		Depth int `db:"depth"`
	}
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE walk (id, depth) AS (
			SELECT id, 1 FROM %[2]q WHERE id = any(?::uuid[]) AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL
			UNION
			SELECT t.id, w.depth + 1 FROM walk w JOIN %[1]q r ON r.source_id = w.id AND r.attribute = ? JOIN %[2]q t ON t.id = r.target_id AND t.resource_type = ? AND t.deleted_at IS NULL WHERE w.depth <= ?
		)
		SELECT coalesce(max(depth), 0) AS depth FROM walk`, scimReferences, Resource{}.TableName()),
		uuidStrings(ids), s.ProviderID, s.ResourceType, attribute, s.ResourceType, query.MaxDepth,
	).First(&walk)
	return walk.Depth, errors.Wrap(err, "error finding SCIM depth")
}

func (s Scope) deleteReferences(tx *storage.Connection, id uuid.UUID) error {
	err := tx.RawQuery(fmt.Sprintf("DELETE FROM %q WHERE source_id = ? OR target_id = ?", scimReferences), id, id).Exec()
	return errors.Wrap(err, "error deleting SCIM references")
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
