package query

import (
	"uuid"

	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type derived struct {
	named
	source string
	via    string
}

func Derived(attribute, source, via string) Reference {
	return derived{named: named(attribute), source: source, via: via}
}

func (d derived) Columns() map[string]string {
	return map[string]string{ValueAttribute: "chain.id"}
}

func (d derived) Exists(provider uuid.UUID, inner string, args []any) (string, []any) {
	source := models.QuoteLiteral(d.source)
	return `scim_resources.id = any(array(SELECT target_id FROM scim_resource_references WHERE attribute = ? AND source_id IN (WITH RECURSIVE walk (id, depth) AS (
		SELECT chain.id, 1 FROM scim_resources chain WHERE chain.sso_provider_id = ? AND chain.resource_type = ` + source + ` AND chain.deleted_at IS NULL AND ` + inner + `
		UNION
		SELECT edge.target_id, walk.depth + 1 FROM walk JOIN scim_resource_references edge ON edge.source_id = walk.id AND edge.attribute = ? AND edge.target_type = ` + source + ` WHERE walk.depth < ?
	) SELECT DISTINCT id FROM walk)))`, append(append([]any{d.via, provider.String()}, args...), d.via, models.SCIMMaxDepth)
}

func (d derived) Extract(any) ([]uuid.UUID, error) {
	return nil, nil
}

func (d derived) Link(*storage.Connection, models.SCIMScope, uuid.UUID, []uuid.UUID) error {
	return nil
}

func (d derived) Load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	ancestors, err := scope.FindAncestors(tx, ids, d.via)
	for _, ancestor := range ancestors {
		kind := "indirect"
		if ancestor.Depth == 1 {
			kind = "direct"
		}
		entry := element(ancestor.SourceID, locations[d.source], kind)
		if ancestor.Display != nil {
			entry["display"] = *ancestor.Display
		}
		elements[ancestor.TargetID] = append(elements[ancestor.TargetID], entry)
	}
	return elements, err
}
