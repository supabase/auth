package query

import (
	"slices"
	"strings"
	"uuid"

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
	provider   uuid.UUID
	location   string
	references []Reference
}

func NewEvaluator(schemas core.Schemas, provider uuid.UUID, location string, references ...Reference) protocol.Evaluator[Clause] {
	return Evaluator{schemas: schemas, provider: provider, location: location, references: references}
}

func (e Evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Clause, error) {
	if name, ok := e.column(attribute); ok {
		return column(name, e.location, op, value)
	}
	if text, ok := value.(string); ok && op == filter.OpStartsWith {
		if clause, ok := prefix(e.name(attribute), strings.ToLower(text)); ok {
			return clause, nil
		}
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return e.compare(attribute, op, value), nil
	}
	leaf, err := match(ref, attribute.Definition, op, value)
	if err != nil {
		return nil, err
	}
	return e.wrap(attribute, ref, leaf), nil
}

func (e Evaluator) Present(attribute *protocol.Attribute) (Clause, error) {
	if _, ok := e.column(attribute); ok {
		return predicate{text: "TRUE"}, nil
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return jsonpath{present{e.path(attribute)}}, nil
	}
	if _, ok := ref.Columns()[attribute.Definition.Name]; !ok && attribute.Definition.Name != ref.Name() {
		return nil, unfilterable(ref, attribute.Definition)
	}
	return e.wrap(attribute, ref, predicate{text: "TRUE"}), nil
}

func (e Evaluator) And(l, r Clause) (Clause, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return jsonpath{and{lpath.expr, rpath.expr}}, nil
	}
	return junction{"AND", l, r}, nil
}

func (e Evaluator) Or(l, r Clause) (Clause, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return jsonpath{or{lpath.expr, rpath.expr}}, nil
	}
	return junction{"OR", l, r}, nil
}

func (e Evaluator) Not(operand Clause) (Clause, error) {
	if path, ok := operand.(jsonpath); ok {
		return jsonpath{not{path.expr}}, nil
	}
	return negation{operand}, nil
}

func (e Evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Clause, error)) (Clause, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	if ref, ok := e.reference(attribute); ok {
		return reference{ref, e.provider, inner}, nil
	}
	path, ok := inner.(jsonpath)
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return jsonpath{exists{e.path(attribute), path.expr}}, nil
}

func (e Evaluator) compare(attribute *protocol.Attribute, op filter.Operator, value any) Clause {
	folded := jsonpath{compare{e.path(attribute), op, value, false}}
	if _, text := value.(string); !text || !attribute.Definition.CaseExact {
		return folded
	}
	exact := exact{compare{e.path(attribute), op, value, true}}
	if !narrowing[op] {
		return exact
	}
	return junction{"AND", folded, exact}
}

func (e Evaluator) wrap(attribute *protocol.Attribute, ref Reference, leaf Clause) Clause {
	if attribute.Parent != nil {
		return leaf
	}
	return reference{ref, e.provider, leaf}
}

func (e Evaluator) reference(attribute *protocol.Attribute) (Reference, bool) {
	top := attribute.Parent
	if top == nil {
		base := e.schemas.Base()
		if attribute.Path.URI != "" && e.schemas.Lookup(core.SchemaURI(attribute.Path.URI)) != base {
			return nil, false
		}
		top = base.Attributes.Lookup(attribute.Path.Name)
	}
	if top == nil {
		return nil, false
	}
	index := slices.IndexFunc(e.references, func(ref Reference) bool { return ref.Name() == top.Name })
	if index < 0 {
		return nil, false
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
