package query

func (r Reference) exists(inner Clause) Clause {
	text, args := inner.SQL()
	return predicate{"EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + text + ")", append([]any{r.Path()}, args...)}
}

func (r Reference) edgeSelect(locations map[string]string) string {
	return `(SELECT json_agg(json_build_object('value', target_id, '$ref', ` + endpoint(locations, "target_type") + ` || target_id, 'type', target_type)) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + QuoteLiteral(r.Path()) + r.scoped() + `)`
}

func (r Reference) scoped() string {
	if r.only == nil {
		return ""
	}
	return ` AND target_id = any(ARRAY[` + literals(r.only) + `]::uuid[])`
}
