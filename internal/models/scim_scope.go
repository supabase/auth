package models

import (
	"database/sql"
	"fmt"
	"strings"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const SCIMMaxDepth = 8

const scimResourceColumns = "id, sso_provider_id, resource_type, resource, created_at, updated_at, deleted_at"

type SCIMAncestor struct {
	TargetID uuid.UUID `db:"target_id"`
	SourceID uuid.UUID `db:"source_id"`
	Depth    int       `db:"depth"`
	Longest  int       `db:"longest"`
	Display  *string   `db:"display"`
}

type SCIMReference struct {
	SourceID   uuid.UUID `db:"source_id"`
	TargetID   uuid.UUID `db:"target_id"`
	TargetType string    `db:"target_type"`
}

func (SCIMReference) TableName() string {
	return "scim_resource_references"
}

type SCIMScope struct {
	ProviderID   uuid.UUID
	ResourceType string
}

func (s SCIMScope) Query(tx *storage.Connection) *pop.Query {
	return tx.Q().
		Where("sso_provider_id = ?", s.ProviderID).
		Where("resource_type = " + QuoteLiteral(s.ResourceType)).
		Where("deleted_at IS NULL")
}

func (s SCIMScope) Find(tx *storage.Connection, id uuid.UUID) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := s.Query(tx).Where("id = ?", id).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM resource")
	}
	return resource, nil
}

func (s SCIMScope) Create(tx *storage.Connection, document string) (*SCIMResource, error) {
	resource := &SCIMResource{}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource_type, resource) VALUES (?, ?, ?, ?::jsonb) RETURNING %s", resource.TableName(), scimResourceColumns),
		uuid.NewV7(), s.ProviderID, s.ResourceType, document,
	).First(resource)
	return resource, err
}

func (s SCIMScope) Update(tx *storage.Connection, id uuid.UUID, document, version string) (*SCIMResource, error) {
	resource := &SCIMResource{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at) RETURNING %s", resource.TableName(), scimResourceColumns),
		document, id, s.ProviderID, s.ResourceType, SCIMVersionTime(version),
	).First(resource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, SCIMNotFoundError{}
		}
		return nil, err
	}
	return resource, nil
}

func (s SCIMScope) Delete(tx *storage.Connection, id uuid.UUID, version string) error {
	count, err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET deleted_at = now() WHERE id = ? AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL AND updated_at = COALESCE(?, updated_at)", SCIMResource{}.TableName()),
		id, s.ProviderID, s.ResourceType, SCIMVersionTime(version),
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return SCIMNotFoundError{}
	}
	return nil
}

func (s SCIMScope) AddReferences(tx *storage.Connection, source uuid.UUID, attribute string, types []string, targets []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return added, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (sso_provider_id, source_id, attribute, target_id, target_type) SELECT sso_provider_id, ?, ?, id, resource_type FROM %q WHERE sso_provider_id = ? AND resource_type = any(?::text[]) AND deleted_at IS NULL AND id = any(?::uuid[]) RETURNING target_id", SCIMReference{}.TableName(), SCIMResource{}.TableName()),
		source, attribute, s.ProviderID, types, uuidStrings(targets),
	).All(&added)
	return added, errors.Wrap(err, "error adding SCIM references")
}

func (s SCIMScope) RemoveReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE source_id = ? AND attribute = ? AND target_id = any(?::uuid[])", SCIMReference{}.TableName()),
		source, attribute, uuidStrings(targets),
	).Exec(), "error removing SCIM references")
}

func (s SCIMScope) FindReferences(tx *storage.Connection, sources []uuid.UUID, attribute string) ([]SCIMReference, error) {
	references := []SCIMReference{}
	if len(sources) == 0 {
		return references, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT r.source_id, r.target_id, t.resource_type AS target_type FROM %q r JOIN %q t ON t.id = r.target_id AND t.deleted_at IS NULL WHERE r.source_id = any(?::uuid[]) AND r.attribute = ? ORDER BY r.source_id, r.target_id", SCIMReference{}.TableName(), SCIMResource{}.TableName()),
		uuidStrings(sources), attribute,
	).All(&references)
	return references, errors.Wrap(err, "error finding SCIM references")
}

func (s SCIMScope) FindTargets(tx *storage.Connection, source uuid.UUID, attribute string) ([]uuid.UUID, error) {
	targets := []uuid.UUID{}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT target_id FROM %q WHERE source_id = ? AND attribute = ?", SCIMReference{}.TableName()),
		source, attribute,
	).All(&targets)
	return targets, errors.Wrap(err, "error finding SCIM targets")
}

func (s SCIMScope) FindAncestors(tx *storage.Connection, targets []uuid.UUID, attribute string) ([]SCIMAncestor, error) {
	ancestors := []SCIMAncestor{}
	if len(targets) == 0 {
		return ancestors, nil
	}
	table := SCIMReference{}.TableName()
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE chain (target_id, source_id, depth) AS (
			SELECT target_id, source_id, 1 FROM %q WHERE target_id = any(?::uuid[]) AND attribute = ?
			UNION
			SELECT c.target_id, r.source_id, c.depth + 1 FROM chain c JOIN %q r ON r.target_id = c.source_id AND r.attribute = ? WHERE c.depth < ?
		)
		SELECT c.target_id, c.source_id, min(c.depth) AS depth, max(c.depth) AS longest, s.resource->>'displayName' AS display
		FROM chain c JOIN %q s ON s.id = c.source_id
		GROUP BY c.target_id, c.source_id, s.id ORDER BY c.target_id, depth, c.source_id`, table, table, SCIMResource{}.TableName()),
		uuidStrings(targets), attribute, attribute, SCIMMaxDepth,
	).All(&ancestors)
	return ancestors, errors.Wrap(err, "error finding SCIM ancestors")
}

func (s SCIMScope) Depth(tx *storage.Connection, ids []uuid.UUID, attribute string) (int, error) {
	var walk struct {
		Depth int `db:"depth"`
	}
	err := tx.RawQuery(
		fmt.Sprintf(`WITH RECURSIVE walk (id, depth) AS (
			SELECT id, 1 FROM %[2]q WHERE id = any(?::uuid[]) AND sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL
			UNION
			SELECT t.id, w.depth + 1 FROM walk w JOIN %[1]q r ON r.source_id = w.id AND r.attribute = ? JOIN %[2]q t ON t.id = r.target_id AND t.resource_type = ? AND t.deleted_at IS NULL WHERE w.depth <= ?
		)
		SELECT coalesce(max(depth), 0) AS depth FROM walk`, SCIMReference{}.TableName(), SCIMResource{}.TableName()),
		uuidStrings(ids), s.ProviderID, s.ResourceType, attribute, s.ResourceType, SCIMMaxDepth,
	).First(&walk)
	return walk.Depth, errors.Wrap(err, "error finding SCIM depth")
}

func (s SCIMScope) DeleteReferences(tx *storage.Connection, id uuid.UUID) error {
	err := tx.RawQuery(fmt.Sprintf("DELETE FROM %q WHERE source_id = ? OR target_id = ?", SCIMReference{}.TableName()), id, id).Exec()
	return errors.Wrap(err, "error deleting SCIM references")
}

func QuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func IsQueryCanceledError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.QueryCanceled
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
