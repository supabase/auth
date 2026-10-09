package query

import (
	"strconv"
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

func (d derived) Select(locations map[string]string) string {
	via := models.QuoteLiteral(d.via)
	return `(SELECT json_agg(json_build_object('value', walk.id, '$ref', ` + models.QuoteLiteral(locations[d.source]+"/") + ` || walk.id, 'type', CASE WHEN walk.depth = 1 THEN 'direct' ELSE 'indirect' END, 'display', source.resource ->> 'displayName') ORDER BY walk.depth, walk.id) FROM (WITH RECURSIVE chain (id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + via + `
		UNION
		SELECT edge.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references edge ON edge.target_id = chain.id AND edge.attribute = ` + via + ` WHERE chain.depth < ` + strconv.Itoa(models.SCIMMaxDepth) + `
	) SELECT id, min(depth) AS depth FROM chain GROUP BY id) walk JOIN scim_resources source ON source.id = walk.id)`
}
