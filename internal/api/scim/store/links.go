package store

import (
	"slices"
	"strconv"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

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
	text, args := "SELECT target_id FROM scim_resource_references WHERE source_id = ? AND attribute = ?", []any{source, attribute}
	if only != nil {
		text, args = text+" AND target_id = any(?::uuid[])", append(args, only)
	}
	err := tx.RawQuery(text, args...).All(&targets)
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

func (s Scope) link(tx *storage.Connection, source uuid.UUID, l Link) error {
	attribute := l.Attribute
	wanted, err := linkTargets(attribute, l.Values)
	if err != nil {
		return err
	}
	current, err := s.findTargets(tx, source, attribute, l.Only)
	if err != nil {
		return err
	}
	add, remove := linkDiff(current, wanted)
	if l.Nested {
		if err := s.nestable(tx, source, attribute, add); err != nil {
			return err
		}
	}
	added, err := s.addReferences(tx, source, attribute, l.Types, add)
	if err != nil {
		return err
	}
	found := make(map[uuid.UUID]bool, len(added))
	for _, id := range added {
		found[id] = true
	}
	if i := slices.IndexFunc(add, func(id uuid.UUID) bool { return !found[id] }); i >= 0 {
		return linkInvalid(attribute, add[i].String())
	}
	return s.removeReferences(tx, source, attribute, remove)
}

func (s Scope) nestable(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	ancestors, err := s.findAncestors(tx, source, attribute)
	if err != nil {
		return err
	}
	level := 1
	for _, ancestor := range ancestors {
		level = max(level, ancestor.Longest+1)
	}
	for _, target := range targets {
		if target == source || slices.ContainsFunc(ancestors, func(ancestor Ancestor) bool { return ancestor.SourceID == target }) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + attribute + " cyclic")
		}
	}
	height, err := s.depth(tx, targets, attribute)
	if err != nil {
		return err
	}
	if height > 0 && level+height > query.MaxDepth {
		return scimerrors.ErrInvalidValue(attribute + " would nest more than " + strconv.Itoa(query.MaxDepth) + " levels deep")
	}
	return nil
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func linkTargets(attribute string, raw any) ([]uuid.UUID, error) {
	elements, _ := raw.([]any)
	wanted := make([]uuid.UUID, 0, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)[query.ValueAttribute].(string)
		id, err := uuid.Parse(value)
		if err != nil {
			return nil, linkInvalid(attribute, value)
		}
		wanted = append(wanted, id)
	}
	return wanted, nil
}

func linkInvalid(attribute, value string) error {
	return scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + attribute + " value")
}

func linkDiff(current, wanted []uuid.UUID) (add, remove []uuid.UUID) {
	have := make(map[uuid.UUID]bool, len(current))
	for _, id := range current {
		have[id] = true
	}
	for _, id := range wanted {
		if _, ok := have[id]; !ok {
			add = append(add, id)
		}
		have[id] = false
	}
	for id, stale := range have {
		if stale {
			remove = append(remove, id)
		}
	}
	return add, remove
}
