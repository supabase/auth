package query

import "uuid"

const uuidPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

func (r Reference) singleExists(provider uuid.UUID, inner string, args []any) (string, []any) {
	matches := `(SELECT lower(string_agg(` + QuoteLiteral(path{"$", r.keys()}.String()+" == ") + ` || to_jsonb(target.id::text)::text, ' || ')) FROM scim_resources target` +
		` WHERE target.sso_provider_id = ? AND target.resource_type IN (` + literals(r.targets) + `) AND target.deleted_at IS NULL AND ` + inner + `)`
	args = append([]any{provider.String()}, args...)
	return `(` + matches + ` IS NOT NULL AND scim_resources.search @@ ` + matches + `::jsonpath)`, append(args, args...)
}

func (r Reference) singleSelect(locations map[string]string) string {
	value := r.value()
	related := `jsonb_strip_nulls(jsonb_build_object('$ref', ` + endpoint(locations, "target.resource_type") + ` || target.id`
	if shown := r.shown(); shown != "" {
		related += `, ` + QuoteLiteral(shown) + `, target.resource ->> ` + QuoteLiteral(r.display)
	}
	return `(SELECT ` + related + `)) FROM scim_resources target WHERE target.id = (CASE WHEN ` + value + ` ~ ` + QuoteLiteral(uuidPattern) + ` THEN ` + value + ` END)::uuid` +
		` AND target.sso_provider_id = scim_resources.sso_provider_id AND target.resource_type IN (` + literals(r.targets) + `) AND target.deleted_at IS NULL)`
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
