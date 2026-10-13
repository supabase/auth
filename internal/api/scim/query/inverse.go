package query

import "strconv"

func (r Reference) inverseSelect(locations map[string]string) string {
	via := QuoteLiteral(r.via.Attribute)
	return `(SELECT json_agg(json_build_object('value', walk.id, '$ref', ` + QuoteLiteral(locations[r.via.Type]+"/") + ` || walk.id, 'type', CASE WHEN walk.depth = 1 THEN 'direct' ELSE 'indirect' END, ` + QuoteLiteral(r.shown()) + `, source.resource ->> ` + QuoteLiteral(r.display) + `) ORDER BY walk.depth, walk.id) FROM (WITH RECURSIVE chain (id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + via + `
		UNION
		SELECT edge.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references edge ON edge.target_id = chain.id AND edge.attribute = ` + via + ` WHERE chain.depth < ` + strconv.Itoa(MaxDepth) + `
	) SELECT id, min(depth) AS depth FROM chain GROUP BY id) walk JOIN scim_resources source ON source.id = walk.id)`
}
