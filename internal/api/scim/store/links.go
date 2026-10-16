package store

import (
	"slices"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/store"
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

func (sc scope) relink(tx *storage.Connection, source uuid.UUID, links []store.Link) error {
	return sc.each(tx, source, links, sc.link)
}

func (sc scope) attach(tx *storage.Connection, source uuid.UUID, links []store.Link) error {
	return sc.each(tx, source, links, sc.add)
}

func (sc scope) each(tx *storage.Connection, source uuid.UUID, links []store.Link, apply func(*storage.Connection, uuid.UUID, store.Link) ([]string, error)) error {
	changed := []string{}
	for _, l := range links {
		touched, err := apply(tx, source, l)
		if err != nil {
			return err
		}
		changed = append(changed, touched...)
	}
	return sc.bump(tx, source, changed)
}

func (sc scope) link(tx *storage.Connection, source uuid.UUID, l store.Link) ([]string, error) {
	current, err := sc.findTargets(tx, source, l.Attribute)
	if err != nil {
		return nil, err
	}
	add, remove := store.LinkDiff(current, l.Targets)
	if !l.Soft {
		if err := sc.acyclic(tx, source, l.Attribute, add); err != nil {
			return nil, err
		}
	}
	if err := sc.connect(tx, source, l, add); err != nil {
		return nil, err
	}
	return append(add, remove...), sc.removeReferences(tx, source, l.Attribute, remove)
}

func (sc scope) add(tx *storage.Connection, source uuid.UUID, l store.Link) ([]string, error) {
	add, _ := store.LinkDiff(nil, l.Targets)
	return add, sc.connect(tx, source, l, add)
}

func (sc scope) connect(tx *storage.Connection, source uuid.UUID, l store.Link, add []string) error {
	added, err := sc.addReferences(tx, source, l.Attribute, l.Types, add)
	if err != nil {
		return err
	}
	if !l.Soft && len(added) < len(add) {
		i := slices.IndexFunc(add, func(id string) bool { return !slices.Contains(added, id) })
		return linkInvalid(l.Attribute, add[i])
	}
	return nil
}

func (sc scope) addReferences(tx *storage.Connection, source uuid.UUID, attribute string, types, targets []string) ([]string, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return nil, nil
	}
	err := tx.RawQuery(
		insertReferences,
		source, attribute, sc.providerID, types, targets,
	).All(&added)
	return uuidStrings(added), errors.Wrap(err, "error adding SCIM references")
}

func (sc scope) removeReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		deleteReferences,
		source, attribute, targets,
	).Exec(), "error removing SCIM references")
}

func (sc scope) findTargets(tx *storage.Connection, source uuid.UUID, attribute string) ([]string, error) {
	targets := []uuid.UUID{}
	err := tx.RawQuery(selectTargets, source, attribute).All(&targets)
	return uuidStrings(targets), errors.Wrap(err, "error finding SCIM targets")
}
