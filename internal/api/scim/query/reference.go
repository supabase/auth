package query

import (
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
	return always, nil
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

func (r Reference) exists(inner Clause) Clause {
	text, args := inner.SQL()
	return predicate{"EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + text + ")", append([]any{r.Path()}, args...)}
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
