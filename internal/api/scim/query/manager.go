package query

import (
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
)

const displayNameAttribute = "displayName"

const uuidPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

type manager struct {
	named
	schema core.SchemaURI
	source string
}

func Manager(attribute string, schema core.SchemaURI, source string) Reference {
	return manager{named: named(attribute), schema: schema, source: source}
}

func (m manager) Targets() []string {
	return nil
}

func (m manager) Columns() map[string]string {
	return map[string]string{displayNameAttribute: displayNameAttribute}
}

func (m manager) Leaf(attribute string, op filter.Operator, value any) (Clause, bool) {
	key, ok := m.Columns()[attribute]
	if !ok {
		return nil, false
	}
	related := path{"$", []string{key}}
	if op == filter.OpPresent {
		return jsonpath(present(related)), true
	}
	return jsonpath(compare(related, op, value)), true
}

func (m manager) Exists(provider uuid.UUID, inner string, args []any) (string, []any) {
	return `EXISTS (SELECT 1 FROM scim_resources mgr WHERE mgr.sso_provider_id = ? AND mgr.resource_type = ` + QuoteLiteral(m.source) +
		` AND mgr.deleted_at IS NULL AND ` + inner + ` AND scim_resources.search @@ lower(` +
		QuoteLiteral(m.jsonpath()+" == ") + ` || to_jsonb(mgr.id::text)::text)::jsonpath)`, append([]any{provider.String()}, args...)
}

func (m manager) Select(locations map[string]string) string {
	return `(SELECT jsonb_strip_nulls(jsonb_build_object(` + QuoteLiteral(string(m.schema)) + `, jsonb_build_object(` + QuoteLiteral(m.Name()) +
		`, jsonb_build_object('$ref', ` + QuoteLiteral(locations[m.source]+"/") + ` || mgr.id, 'displayName', mgr.resource ->> 'displayName'))))` +
		` FROM scim_resources mgr WHERE mgr.id = (CASE WHEN ` + m.value() + ` ~ ` + QuoteLiteral(uuidPattern) + ` THEN ` + m.value() + ` END)::uuid` +
		` AND mgr.sso_provider_id = scim_resources.sso_provider_id AND mgr.resource_type = ` + QuoteLiteral(m.source) + ` AND mgr.deleted_at IS NULL)`
}

func (m manager) Strip(document core.Object) {
	extension, _ := document.Get(string(m.schema)).(map[string]any)
	value, _ := extension[m.Name()].(map[string]any)
	for _, key := range []string{displayNameAttribute, "$ref"} {
		delete(value, key)
	}
}

func (m manager) keys() []string {
	return []string{string(m.schema), m.Name(), ValueAttribute}
}

func (m manager) value() string {
	quoted := make([]string, len(m.keys()))
	for i, key := range m.keys() {
		quoted[i] = QuoteLiteral(key)
	}
	return `scim_resources.resource #>> ARRAY[` + strings.Join(quoted, ", ") + `]`
}

func (m manager) jsonpath() string {
	return path{"$", m.keys()}.String()
}
