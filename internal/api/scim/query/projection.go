package query

func (r Reference) selection() string {
	return "json_build_object(" + quoteLiteral(r.Name()) + ", " + r.subquery() + ")"
}

func (r Reference) subquery() string {
	if r.kind == inverse {
		return `(SELECT json_agg(json_build_object('value', source_id) ORDER BY source_id) FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + quoteLiteral(r.via) + `)`
	}
	return `(SELECT json_agg(json_build_object('value', target_id) ORDER BY target_id) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + quoteLiteral(r.Name()) + `)`
}
