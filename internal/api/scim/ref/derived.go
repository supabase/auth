package ref

import (
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/api/scim/query"
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
	return map[string]string{query.ValueAttribute: "chain.source_id"}
}

func (d derived) Exists(inner string, args []any) (string, []any) {
	return `scim_resources.id IN (WITH RECURSIVE down (id) AS (
		SELECT chain.target_id FROM scim_resource_references chain WHERE chain.attribute = ? AND ` + inner + `
		UNION
		SELECT edge.target_id FROM down JOIN scim_resource_references edge ON edge.source_id = down.id AND edge.attribute = ?
	) SELECT id FROM down)`, append(append([]any{d.via}, args...), d.via)
}

func (d derived) Resolve(schemas core.Schemas) Reference {
	d.named, _ = d.canonical(schemas)
	return d
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
