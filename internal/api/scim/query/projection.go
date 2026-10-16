package query

import "fmt"

const inverseSubquery = `(
  SELECT json_agg(json_build_object('value', id, 'type', type) ORDER BY id)
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
  SELECT json_agg(json_build_object('value', target_id) ORDER BY target_id)
  FROM scim_resource_references
  WHERE source_id = scim_resources.id
    AND attribute = %s
)`

func (r Reference) selection() string {
	return "json_build_object(" + quoteLiteral(r.Name) + ", " + r.subquery() + ")"
}

func (r Reference) subquery() string {
	if r.Inverse() {
		return fmt.Sprintf(inverseSubquery, quoteLiteral(r.InverseOf))
	}
	return fmt.Sprintf(memberSubquery, quoteLiteral(r.Name))
}
