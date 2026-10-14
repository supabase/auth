package query

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

type projection struct {
	locations map[string]string
	only      []string
}

func (p projection) subquery(r Reference) string {
	switch r.kind {
	case multi:
		return p.edge(r)
	case inverse:
		return p.inverse(r)
	}
	return p.single(r)
}

func (p projection) part(r Reference) string {
	if r.uri == "" {
		return "json_build_object(" + QuoteLiteral(r.Name()) + ", " + p.subquery(r) + ")"
	}
	return "(SELECT json_build_object(" + QuoteLiteral(string(r.uri)) + ", json_build_object(" + QuoteLiteral(r.Name()) + ", v)) FROM (SELECT " + p.subquery(r) + ") x(v) WHERE v IS NOT NULL)"
}

func (p projection) inverse(r Reference) string {
	via := QuoteLiteral(r.via.Attribute)
	return `(SELECT json_agg(json_build_object('value', walk.id, '$ref', ` + QuoteLiteral(p.locations[r.via.Type]+"/") + ` || walk.id, 'type', CASE WHEN walk.depth = 1 THEN 'direct' ELSE 'indirect' END` + p.display(r, "source") + `) ORDER BY walk.depth, walk.id) FROM (WITH RECURSIVE chain (id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + via + `
		UNION
		SELECT edge.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references edge ON edge.target_id = chain.id AND edge.attribute = ` + via + ` WHERE chain.depth < ` + strconv.Itoa(MaxDepth) + `
	) SELECT id, min(depth) AS depth FROM chain GROUP BY id) walk JOIN scim_resources source ON source.id = walk.id)`
}

func (p projection) edge(r Reference) string {
	return `(SELECT json_agg(json_build_object('value', target_id, '$ref', ` + endpoint(p.locations, "target_type") + ` || target_id, 'type', target_type)) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + QuoteLiteral(r.Path()) + p.scoped() + `)`
}

func (p projection) scoped() string {
	if p.only == nil {
		return ""
	}
	return ` AND target_id = any(ARRAY[` + literals(p.only) + `]::uuid[])`
}

func (p projection) single(r Reference) string {
	value := p.value(r)
	related := `jsonb_strip_nulls(jsonb_build_object('$ref', ` + endpoint(p.locations, "target.resource_type") + ` || target.id` + p.display(r, "target")
	return `(SELECT ` + related + `)) FROM scim_resources target WHERE target.id = (CASE WHEN ` + value + ` ~ ` + QuoteLiteral(uuidPattern) + ` THEN ` + value + ` END)::uuid` +
		` AND target.sso_provider_id = scim_resources.sso_provider_id AND target.resource_type IN (` + literals(r.targets) + `) AND target.deleted_at IS NULL)`
}

func (p projection) display(r Reference, table string) string {
	shown := r.shown()
	if shown == "" {
		return ""
	}
	return `, ` + QuoteLiteral(shown) + `, ` + table + `.resource ->> ` + QuoteLiteral(displayNameAttribute)
}

func (p projection) keys(r Reference) []string {
	keys := []string{r.Name(), ValueAttribute}
	if r.uri != "" {
		keys = append([]string{string(r.uri)}, keys...)
	}
	return keys
}

func (p projection) value(r Reference) string {
	return `scim_resources.resource #>> ARRAY[` + literals(p.keys(r)) + `]`
}

func literals(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = QuoteLiteral(value)
	}
	return strings.Join(quoted, ", ")
}

func endpoint(locations map[string]string, kind string) string {
	var s strings.Builder
	s.WriteString("CASE " + kind)
	for _, name := range slices.Sorted(maps.Keys(locations)) {
		s.WriteString(" WHEN " + QuoteLiteral(name) + " THEN " + QuoteLiteral(locations[name]+"/"))
	}
	s.WriteString(" END")
	return s.String()
}
