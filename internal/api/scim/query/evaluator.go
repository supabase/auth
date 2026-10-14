package query

import (
	"slices"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var _ protocol.Evaluator[Clause] = evaluator{}

type evaluator struct {
	schemas    core.Schemas
	location   string
	references []Reference
}

func (e evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Clause, error) {
	f := e.field(attribute)
	if value == nil {
		if op != filter.OpEquals && op != filter.OpNotEquals {
			return never, nil
		}
		present, err := f.present()
		if err != nil || op == filter.OpNotEquals {
			return present, err
		}
		return not(present), nil
	}
	clause, err := e.assigned(f, op, value)
	if err != nil || !f.unassignable(op) {
		return clause, err
	}
	present, err := f.present()
	if err != nil {
		return nil, err
	}
	return or(clause, not(present)), nil
}

func (e evaluator) Present(attribute *protocol.Attribute) (Clause, error) {
	return e.field(attribute).present()
}

func (e evaluator) And(l, r Clause) (Clause, error) {
	return and(l, r), nil
}

func (e evaluator) Or(l, r Clause) (Clause, error) {
	return or(l, r), nil
}

func (e evaluator) Not(operand Clause) (Clause, error) {
	return not(operand), nil
}

func (e evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Clause, error)) (Clause, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	f := e.field(attribute)
	if f.linked {
		return f.ref.exists(inner), nil
	}
	path, ok := inner.(jsonpath)
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return jsonpath(f.path.exists(path)), nil
}

func (e evaluator) assigned(f field, op filter.Operator, value any) (Clause, error) {
	if f.column() {
		return column(f.name, e.location, op, value)
	}
	if text, ok := value.(string); ok {
		if clause, ok := indexed(e.schemas.Base().ID, f.name, op, text, f.attribute.Definition.CaseExact); ok {
			return clause, nil
		}
	}
	return f.match(op, value)
}

func (e evaluator) field(attribute *protocol.Attribute) field {
	ref, linked := e.reference(attribute)
	return field{attribute: attribute, name: e.name(attribute), path: e.path(attribute), ref: ref, linked: linked}
}

func (e evaluator) reference(attribute *protocol.Attribute) (Reference, bool) {
	if attribute.Parent != nil {
		return e.lookup(attribute.Parent)
	}
	top, _ := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, "")
	ref, ok := e.lookup(top)
	return ref, ok && ref.resolves(attribute.Definition.Name)
}

func (e evaluator) lookup(top *core.Attribute) (Reference, bool) {
	index := slices.IndexFunc(e.references, func(ref Reference) bool { return ref.attribute == top })
	if top == nil || index < 0 {
		return Reference{}, false
	}
	return e.references[index], true
}

func (e evaluator) path(attribute *protocol.Attribute) path {
	if attribute.Parent != nil {
		return path{"@", []string{attribute.Definition.Name}}
	}
	keys := e.keys(attribute)
	schema := e.schemas.Lookup(core.SchemaURI(attribute.Path.URI))
	if e.schemas.IsExtension(schema) {
		return path{"$", append([]string{string(schema.ID)}, keys...)}
	}
	return path{"$", keys}
}

func (e evaluator) name(attribute *protocol.Attribute) string {
	if attribute.Parent != nil || e.schemas.IsExtension(e.schemas.Lookup(core.SchemaURI(attribute.Path.URI))) {
		return ""
	}
	return strings.Join(e.keys(attribute), ".")
}

func (e evaluator) keys(attribute *protocol.Attribute) []string {
	if top, ok := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, ""); ok && top != attribute.Definition {
		return []string{top.Name, attribute.Definition.Name}
	}
	return []string{attribute.Definition.Name}
}
