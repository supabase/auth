package query

const MaxDepth = 8

type projection struct{}

func (p projection) subquery(r Reference) string {
	if r.kind == inverse {
		return p.inverse(r)
	}
	return p.edge(r)
}

func (p projection) part(r Reference) string {
	return "json_build_object(" + QuoteLiteral(r.Name()) + ", " + p.subquery(r) + ")"
}

func (p projection) inverse(r Reference) string {
	return `(SELECT json_agg(json_build_object('value', source.id) ORDER BY source.id) FROM scim_resource_references edge JOIN scim_resources source ON source.id = edge.source_id WHERE edge.target_id = scim_resources.id AND edge.attribute = ` + QuoteLiteral(r.via.Attribute) + `)`
}

func (p projection) edge(r Reference) string {
	return `(SELECT json_agg(json_build_object('value', target_id)) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + QuoteLiteral(r.Name()) + `)`
}
