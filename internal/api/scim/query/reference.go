package query

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/patch"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

const (
	ValueAttribute       = "value"
	displayNameAttribute = "displayName"
	uuidPattern          = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
)

var edgeColumns = map[string]string{ValueAttribute: "edge.target_id", "type": "lower(target.resource_type)"}

type kind int

const (
	single kind = iota
	multi
	inverse
)

type Edge struct {
	Type      string
	Attribute string
}

type Reference struct {
	attribute *core.Attribute
	uri       core.SchemaURI
	kind      kind
	targets   []string
	via       Edge
	nested    bool
	only      []string
}

func (r Reference) Name() string {
	return r.attribute.Name
}

func (r Reference) Path() string {
	if r.uri == "" {
		return r.Name()
	}
	return string(r.uri) + ":" + r.Name()
}

func (r Reference) Targets() []string {
	if r.kind != multi {
		return nil
	}
	return r.targets
}

func (r Reference) Nested() bool {
	return r.nested
}

func (r Reference) Get(document core.Object) any {
	return r.container(document).Get(r.Name())
}

func (r Reference) Strip(document core.Object) {
	container := r.container(document)
	if r.kind != single {
		container.Remove(r.Name())
		return
	}
	value, _ := container.Get(r.Name()).(map[string]any)
	for _, sub := range r.attribute.SubAttributes {
		if sub.Name == "$ref" || sub.Mutability == core.MutabilityReadOnly {
			delete(value, sub.Name)
		}
	}
}

func (r Reference) Leaf(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if r.kind != multi {
		return nil, r.unfilterable(definition)
	}
	if op != filter.OpPresent {
		return r.match(definition, op, value)
	}
	if _, ok := edgeColumns[definition.Name]; !ok && definition.Name != r.Name() {
		return nil, r.unfilterable(definition)
	}
	return predicate{text: "TRUE"}, nil
}

func (r Reference) Select(locations map[string]string) string {
	switch r.kind {
	case multi:
		return r.edgeSelect(locations)
	case inverse:
		return r.inverseSelect(locations)
	}
	return r.singleSelect(locations)
}

func (r Reference) resolves(sub string) bool {
	return r.kind != single || sub == r.shown()
}

func (r Reference) computed(sub string) bool {
	return r.kind != single || sub != ValueAttribute
}

func (r Reference) container(document core.Object) core.Object {
	if r.uri == "" {
		return document
	}
	extension, _ := document.Get(string(r.uri)).(map[string]any)
	return extension
}

func (r Reference) shown() string {
	for _, name := range []string{"display", displayNameAttribute} {
		if sub := r.attribute.SubAttribute(name); sub != nil {
			return sub.Name
		}
	}
	return ""
}

func (r Reference) part(locations map[string]string) string {
	if r.uri == "" {
		return "json_build_object(" + QuoteLiteral(r.Name()) + ", " + r.Select(locations) + ")"
	}
	return "(SELECT json_build_object(" + QuoteLiteral(string(r.uri)) + ", json_build_object(" + QuoteLiteral(r.Name()) + ", v)) FROM (SELECT " + r.Select(locations) + ") x(v) WHERE v IS NOT NULL)"
}

func (r Reference) inverseSelect(locations map[string]string) string {
	via := QuoteLiteral(r.via.Attribute)
	return `(SELECT json_agg(json_build_object('value', walk.id, '$ref', ` + QuoteLiteral(locations[r.via.Type]+"/") + ` || walk.id, 'type', CASE WHEN walk.depth = 1 THEN 'direct' ELSE 'indirect' END` + r.display("source") + `) ORDER BY walk.depth, walk.id) FROM (WITH RECURSIVE chain (id, depth) AS (
		SELECT source_id, 1 FROM scim_resource_references WHERE target_id = scim_resources.id AND attribute = ` + via + `
		UNION
		SELECT edge.source_id, chain.depth + 1 FROM chain JOIN scim_resource_references edge ON edge.target_id = chain.id AND edge.attribute = ` + via + ` WHERE chain.depth < ` + strconv.Itoa(MaxDepth) + `
	) SELECT id, min(depth) AS depth FROM chain GROUP BY id) walk JOIN scim_resources source ON source.id = walk.id)`
}

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

func (r Reference) match(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(r.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := edgeColumns[definition.Name]
	if !ok {
		return nil, r.unfilterable(definition)
	}
	if definition.Name != ValueAttribute {
		return predicate{column + sign + "lower(?)", []any{text}}, nil
	}
	return uuidPredicate(column, sign, op, text), nil
}

func (r Reference) unfilterable(definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(r.Name()+"."+definition.Name) + " cannot be filtered")
}

func (r Reference) values(op patch.Operation, path filter.Path) []string {
	if r.kind != multi || r.attribute.Required || path.SubAttribute != "" {
		return nil
	}
	switch patch.Op(strings.ToLower(string(op.Op))) {
	case patch.OpAdd:
		return added(op, path)
	case patch.OpRemove:
		return removed(path)
	}
	return nil
}

func resourceTypes(attribute *core.Attribute) []string {
	ref := attribute.SubAttribute("$ref")
	if attribute.Type != core.TypeComplex || ref == nil {
		return nil
	}
	types := []string{}
	for _, t := range ref.ReferenceTypes {
		if t != core.ReferenceExternal && t != core.ReferenceURI {
			types = append(types, string(t))
		}
	}
	return types
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
