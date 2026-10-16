package store

import (
	"fmt"
	"slices"
	"strconv"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

const insertReferences = `
INSERT INTO scim_resource_references (sso_provider_id, source_id, attribute, target_id, target_type)
SELECT sso_provider_id, ?, ?, id, resource_type
FROM scim_resources
WHERE sso_provider_id = ?
  AND resource_type = any(?::text[])
  AND deleted_at IS NULL
  AND id = any(?::uuid[])
RETURNING target_id`

const deleteReferences = `
DELETE FROM scim_resource_references
WHERE source_id = ?
  AND attribute = ?
  AND target_id = any(?::uuid[])`

const selectTargets = `
SELECT target_id
FROM scim_resource_references
WHERE source_id = ?
  AND attribute = ?`

const selectCycle = `
WITH RECURSIVE up (id) AS (
  SELECT ?::uuid
  UNION
  SELECT r.source_id
  FROM up u
  JOIN scim_resource_references r ON r.target_id = u.id AND r.attribute = ?
)
SELECT id
FROM up
WHERE id = any(?::uuid[])
LIMIT 1`

func (s Scope) addReferences(tx *storage.Connection, source uuid.UUID, attribute string, types []string, targets []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return added, nil
	}
	err := tx.RawQuery(
		insertReferences,
		source, attribute, s.providerID, types, uuidStrings(targets),
	).All(&added)
	return added, errors.Wrap(err, "error adding SCIM references")
}

func (s Scope) removeReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		deleteReferences,
		source, attribute, uuidStrings(targets),
	).Exec(), "error removing SCIM references")
}

func (s Scope) findTargets(tx *storage.Connection, source uuid.UUID, attribute string) ([]uuid.UUID, error) {
	targets := []uuid.UUID{}
	err := tx.RawQuery(selectTargets, source, attribute).All(&targets)
	return targets, errors.Wrap(err, "error finding SCIM targets")
}

func (s Scope) acyclic(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	cyclic := []uuid.UUID{}
	err := tx.RawQuery(
		selectCycle,
		source, attribute, uuidStrings(targets),
	).All(&cyclic)
	if err != nil {
		return errors.Wrap(err, "error finding SCIM cycles")
	}
	if len(cyclic) > 0 {
		return scimerrors.ErrInvalidValue(strconv.Quote(cyclic[0].String()) + " would make " + attribute + " cyclic")
	}
	return nil
}

func (s Scope) link(tx *storage.Connection, source uuid.UUID, l Link) error {
	attribute := l.Attribute
	wanted, err := linkTargets(attribute, l.Values)
	if err != nil {
		return err
	}
	current, err := s.findTargets(tx, source, attribute)
	if err != nil {
		return err
	}
	add, remove := linkDiff(current, wanted)
	if err := s.acyclic(tx, source, attribute, add); err != nil {
		return err
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

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func linkTargets(attribute string, raw any) ([]uuid.UUID, error) {
	elements, ok := raw.([]any)
	if raw != nil && !ok {
		return nil, linkInvalid(attribute, fmt.Sprint(raw))
	}
	wanted := make([]uuid.UUID, 0, len(elements))
	for _, element := range elements {
		object, _ := element.(map[string]any)
		value, _ := object[query.ValueAttribute].(string)
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
