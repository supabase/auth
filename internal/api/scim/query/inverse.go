package query

import (
	"strconv"
	"uuid"
)

func (r Reference) inverseExists(provider uuid.UUID, inner string, args []any) (string, []any) {
	source := QuoteLiteral(r.via.Type)
	return `scim_resources.id = any(array(SELECT target_id FROM scim_resource_references WHERE attribute = ? AND source_id IN (WITH RECURSIVE walk (id, depth) AS (
		SELECT chain.id, 1 FROM scim_resources chain WHERE chain.sso_provider_id = ? AND chain.resource_type = ` + source + ` AND chain.deleted_at IS NULL AND ` + inner + `
		UNION
		SELECT edge.target_id, walk.depth + 1 FROM walk JOIN scim_resource_references edge ON edge.source_id = walk.id AND edge.attribute = ? AND edge.target_type = ` + source + ` WHERE walk.depth < ?
	) SELECT DISTINCT id FROM walk)))`, append(append([]any{r.via.Attribute, provider.String()}, args...), r.via.Attribute, MaxDepth)
}

func (r Reference) inverseSelect(locations map[string]string) string {
	via := QuoteLiteral(r.via.Attribute)
	return `(SELECT json_agg(json_build_object('value', walk.id, '$ref', ` + QuoteLiteral(locations[r.via.Type]+"/") + ` || walk.id, 'type', CASE WHEN walk.depth = 1 THEN 'direct' ELSE 'indirect' END, ` + QuoteLiteral(r.shown()) + `, source.resource ->> ` + QuoteLiteral(r.display) + `) ORDER BY walk.depth, walk.id) FROM (WITH RECURSIVE chain (id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + via + `
		UNION
		SELECT edge.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references edge ON edge.target_id = chain.id AND edge.attribute = ` + via + ` WHERE chain.depth < ` + strconv.Itoa(MaxDepth) + `
	) SELECT id, min(depth) AS depth FROM chain GROUP BY id) walk JOIN scim_resources source ON source.id = walk.id)`
}
