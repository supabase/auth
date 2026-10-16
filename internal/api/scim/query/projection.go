package query

import "fmt"

const inverseSubquery = `(
  SELECT jsonb_agg(jsonb_build_object('value', id, 'type', type) ORDER BY id)
  FROM (
    SELECT DISTINCT ON (id) id, type
    FROM (
      WITH RECURSIVE up(id, type) AS (
        SELECT source_id, 'direct'
        FROM scim_resource_references
        WHERE target_id = scim_resources.id AND attribute = %[1]s
        UNION
        SELECT edge.source_id, 'indirect'
        FROM scim_resource_references edge
        JOIN up ON edge.target_id = up.id
        WHERE edge.attribute = %[1]s
      )
      SELECT id, type FROM up
    ) walked
    ORDER BY id, type
  ) deduped
)`

const memberSubquery = `(
  SELECT jsonb_agg(jsonb_build_object('value', target_id, 'type', target_type) ORDER BY target_id)
  FROM scim_resource_references
  WHERE source_id = scim_resources.id
    AND attribute = %s
)`

func (r Reference) Pair() string {
	if r.Inverse() {
		return quoteLiteral(r.Name) + ", " + fmt.Sprintf(inverseSubquery, quoteLiteral(r.InverseOf))
	}
	return quoteLiteral(r.Name) + ", " + fmt.Sprintf(memberSubquery, quoteLiteral(r.Name))
}
