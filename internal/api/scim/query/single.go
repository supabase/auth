package query

const uuidPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

func (r Reference) singleSelect(locations map[string]string) string {
	value := r.value()
	related := `jsonb_strip_nulls(jsonb_build_object('$ref', ` + endpoint(locations, "target.resource_type") + ` || target.id` + r.display("target")
	return `(SELECT ` + related + `)) FROM scim_resources target WHERE target.id = (CASE WHEN ` + value + ` ~ ` + QuoteLiteral(uuidPattern) + ` THEN ` + value + ` END)::uuid` +
		` AND target.sso_provider_id = scim_resources.sso_provider_id AND target.resource_type IN (` + literals(r.targets) + `) AND target.deleted_at IS NULL)`
}

func (r Reference) display(table string) string {
	shown := r.shown()
	if shown == "" {
		return ""
	}
	return `, ` + QuoteLiteral(shown) + `, ` + table + `.resource ->> ` + QuoteLiteral(displayNameAttribute)
}

func (r Reference) keys() []string {
	keys := []string{r.Name(), ValueAttribute}
	if r.uri != "" {
		keys = append([]string{string(r.uri)}, keys...)
	}
	return keys
}

func (r Reference) value() string {
	return `scim_resources.resource #>> ARRAY[` + literals(r.keys()) + `]`
}
