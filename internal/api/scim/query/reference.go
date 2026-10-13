package query

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

const (
	ValueAttribute       = "value"
	displayNameAttribute = "displayName"
)

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

type Declared struct {
	Inverse map[Edge]Edge
	Display map[string]string
}

type Reference struct {
	attribute *core.Attribute
	uri       core.SchemaURI
	kind      kind
	targets   []string
	display   string
	via       Edge
	nested    bool
}

func References(resourceType string, schemas core.Schemas, declared Declared) []Reference {
	references := []Reference{}
	for _, schema := range schemas {
		uri := core.SchemaURI("")
		if schemas.IsExtension(schema) {
			uri = schema.ID
		}
		for _, attribute := range schema.Attributes {
			targets := resourceTypes(attribute)
			if len(targets) == 0 {
				continue
			}
			ref := Reference{attribute: attribute, uri: uri, targets: targets}
			self := Edge{resourceType, ref.Path()}
			via, inverted := declared.Inverse[self]
			switch {
			case inverted:
				ref.kind, ref.via, ref.display = inverse, via, declared.Display[via.Type]
			case attribute.Mutability == core.MutabilityReadOnly:
				continue
			case attribute.MultiValued:
				ref.kind, ref.nested = multi, slices.Contains(slices.Collect(maps.Values(declared.Inverse)), self)
			default:
				ref.kind, ref.display = single, declared.Display[targets[0]]
			}
			references = append(references, ref)
		}
	}
	return references
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
	if r.kind == single {
		if definition.Name != r.shown() {
			return nil, unfilterable(r, definition)
		}
		related := path{"$", []string{r.display}}
		if op == filter.OpPresent {
			return jsonpath(present(related)), nil
		}
		return jsonpath(compare(related, op, value)), nil
	}
	if op != filter.OpPresent {
		return match(r, definition, op, value)
	}
	if _, ok := r.columns()[definition.Name]; !ok && definition.Name != r.Name() {
		return nil, unfilterable(r, definition)
	}
	return predicate{text: "TRUE"}, nil
}

func (r Reference) Exists(provider uuid.UUID, inner string, args []any) (string, []any) {
	switch r.kind {
	case multi:
		return r.edgeExists(inner, args)
	case inverse:
		return r.inverseExists(provider, inner, args)
	}
	return r.singleExists(provider, inner, args)
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

func (r Reference) resolves(sub string) bool {
	return r.kind != single || sub == r.shown()
}

func (r Reference) computed(sub string) bool {
	return r.kind != single || sub != ValueAttribute
}

func (r Reference) columns() map[string]string {
	switch r.kind {
	case multi:
		return map[string]string{ValueAttribute: "edge.target_id", "type": "lower(target.resource_type)"}
	case inverse:
		return map[string]string{ValueAttribute: "chain.id"}
	}
	return nil
}

func (r Reference) part(locations map[string]string) string {
	if r.uri == "" {
		return "json_build_object(" + QuoteLiteral(r.Name()) + ", " + r.Select(locations) + ")"
	}
	return "(SELECT json_build_object(" + QuoteLiteral(string(r.uri)) + ", json_build_object(" + QuoteLiteral(r.Name()) + ", v)) FROM (SELECT " + r.Select(locations) + ") x(v) WHERE v IS NOT NULL)"
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

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := ref.columns()[definition.Name]
	if !ok {
		return nil, unfilterable(ref, definition)
	}
	if definition.Name != ValueAttribute {
		return predicate{column + sign + "lower(?)", []any{text}}, nil
	}
	return uuidPredicate(column, sign, op, text), nil
}

func unfilterable(ref Reference, definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " cannot be filtered")
}
