package query

import (
	"slices"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var narrowing = map[filter.Operator]bool{
	filter.OpEquals:     true,
	filter.OpStartsWith: true,
	filter.OpContains:   true,
	filter.OpEndsWith:   true,
}

type Evaluator struct {
	schemas    core.Schemas
	location   string
	references []Reference
}

func NewEvaluator(schemas core.Schemas, location string, references ...Reference) protocol.Evaluator[Clause] {
	return Evaluator{schemas: schemas, location: location, references: references}
}

func (e Evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Clause, error) {
	if value == nil {
		if op != filter.OpEquals && op != filter.OpNotEquals {
			return predicate{text: "false"}, nil
		}
		present, err := e.Present(attribute)
		if err != nil || op == filter.OpNotEquals {
			return present, err
		}
		return e.Not(present)
	}
	clause, err := e.assigned(attribute, op, value)
	if err != nil || !e.unassignable(attribute, op) {
		return clause, err
	}
	present, err := e.Present(attribute)
	if err != nil {
		return nil, err
	}
	unassigned, _ := e.Not(present)
	return e.Or(clause, unassigned)
}

func (e Evaluator) Present(attribute *protocol.Attribute) (Clause, error) {
	if _, ok := e.column(attribute); ok {
		return predicate{text: "TRUE"}, nil
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return jsonpath(present(e.path(attribute))), nil
	}
	leaf, err := ref.Leaf(attribute.Definition, filter.OpPresent, nil)
	if err != nil {
		return nil, err
	}
	return e.wrap(attribute, ref, leaf), nil
}

func (e Evaluator) And(l, r Clause) (Clause, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return "(" + lpath + " && " + rpath + ")", nil
	}
	return junction("AND", l, r), nil
}

func (e Evaluator) Or(l, r Clause) (Clause, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return "(" + lpath + " || " + rpath + ")", nil
	}
	return junction("OR", l, r), nil
}

func (e Evaluator) Not(operand Clause) (Clause, error) {
	if path, ok := operand.(jsonpath); ok {
		return "!(" + path + ")", nil
	}
	text, args := operand.SQL()
	return predicate{"NOT (" + text + ")", args}, nil
}

func (e Evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Clause, error)) (Clause, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	if ref, ok := e.reference(attribute); ok {
		return ref.exists(inner), nil
	}
	path, ok := inner.(jsonpath)
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return jsonpath(exists(e.path(attribute), path)), nil
}

func (e Evaluator) assigned(attribute *protocol.Attribute, op filter.Operator, value any) (Clause, error) {
	if name, ok := e.column(attribute); ok {
		return column(name, e.location, op, value)
	}
	if text, ok := value.(string); ok {
		if clause, ok := indexed(e.schemas.Base().ID, e.name(attribute), op, text, attribute.Definition.CaseExact); ok {
			return clause, nil
		}
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return e.compare(attribute, op, value), nil
	}
	leaf, err := ref.Leaf(attribute.Definition, op, value)
	if err != nil {
		return nil, err
	}
	return e.wrap(attribute, ref, leaf), nil
}

// RFC 7643 Section 2.5: an unassigned attribute is equivalent to null, so it is not equal to a value.
func (e Evaluator) unassignable(attribute *protocol.Attribute, op filter.Operator) bool {
	_, fixed := e.column(attribute)
	_, linked := e.reference(attribute)
	return op == filter.OpNotEquals && !fixed && (!linked || attribute.Parent == nil)
}

func (e Evaluator) compare(attribute *protocol.Attribute, op filter.Operator, value any) Clause {
	path := compare(e.path(attribute), op, value)
	if _, text := value.(string); !text || !attribute.Definition.CaseExact {
		return jsonpath(path)
	}
	strict := predicate{"resource @@ ?::jsonpath", []any{path}}
	if !narrowing[op] {
		return strict
	}
	return junction("AND", jsonpath(path), strict)
}

func (e Evaluator) wrap(attribute *protocol.Attribute, ref Reference, leaf Clause) Clause {
	if attribute.Parent != nil {
		return leaf
	}
	return ref.exists(leaf)
}

func (e Evaluator) reference(attribute *protocol.Attribute) (Reference, bool) {
	if attribute.Parent != nil {
		return e.lookup(attribute.Parent)
	}
	top, _ := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, "")
	ref, ok := e.lookup(top)
	return ref, ok && ref.resolves(attribute.Definition.Name)
}

func (e Evaluator) lookup(top *core.Attribute) (Reference, bool) {
	index := slices.IndexFunc(e.references, func(ref Reference) bool { return ref.attribute == top })
	if top == nil || index < 0 {
		return Reference{}, false
	}
	return e.references[index], true
}

func (e Evaluator) path(attribute *protocol.Attribute) path {
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

func (e Evaluator) column(attribute *protocol.Attribute) (string, bool) {
	name := e.name(attribute)
	_, ok := Columns[name]
	return name, ok
}

func (e Evaluator) name(attribute *protocol.Attribute) string {
	if attribute.Parent != nil || e.schemas.IsExtension(e.schemas.Lookup(core.SchemaURI(attribute.Path.URI))) {
		return ""
	}
	return strings.Join(e.keys(attribute), ".")
}

func (e Evaluator) keys(attribute *protocol.Attribute) []string {
	if top, ok := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, ""); ok && top != attribute.Definition {
		return []string{top.Name, attribute.Definition.Name}
	}
	return []string{attribute.Definition.Name}
}

func jsonpaths(l, r Clause) (jsonpath, jsonpath, bool) {
	lpath, lok := l.(jsonpath)
	rpath, rok := r.(jsonpath)
	return lpath, rpath, lok && rok
}
