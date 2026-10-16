package store

import (
	"slices"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const selectEdges = `
SELECT source_id, attribute, target_id
FROM scim_resource_references
WHERE source_id = ?
  OR target_id = ?`

const bumpResources = `
UPDATE scim_resources
SET updated_at = greatest(now(), updated_at + interval '1 microsecond')
WHERE sso_provider_id = ?
  AND id = any(?::uuid[])
  AND deleted_at IS NULL`

type edge struct {
	Source    uuid.UUID `db:"source_id"`
	Attribute string    `db:"attribute"`
	Target    uuid.UUID `db:"target_id"`
}

func (sc scope) edges(tx *storage.Connection, id uuid.UUID) ([]edge, error) {
	edges := []edge{}
	err := tx.RawQuery(selectEdges, id, id).All(&edges)
	return edges, errors.Wrap(err, "error finding SCIM edges")
}

func others(id uuid.UUID, edges []edge) []string {
	ends := make([]string, len(edges))
	for i, e := range edges {
		ends[i] = e.Source.String()
		if e.Source == id {
			ends[i] = e.Target.String()
		}
	}
	return ends
}

// RFC 7232 Section 2.1: a weak entity tag changes when the representation changes.
func (sc scope) bump(tx *storage.Connection, source uuid.UUID, ids []string) error {
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == source.String() })
	if len(ids) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(bumpResources, sc.providerID, ids).Exec(), "error bumping SCIM versions")
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
