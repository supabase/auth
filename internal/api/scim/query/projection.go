package query

const MaxDepth = 8

func (r Reference) selection() string {
	return "json_build_object(" + quoteLiteral(r.Name()) + ", " + r.subquery() + ")"
}

func (r Reference) subquery() string {
	if r.kind == inverse {
		return `(SELECT json_agg(json_build_object('value', source.id) ORDER BY source.id) FROM scim_resource_references edge JOIN scim_resources source ON source.id = edge.source_id WHERE edge.target_id = scim_resources.id AND edge.attribute = ` + quoteLiteral(r.via.Attribute) + `)`
	}
	return `(SELECT json_agg(json_build_object('value', target_id)) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + quoteLiteral(r.Name()) + `)`
}
