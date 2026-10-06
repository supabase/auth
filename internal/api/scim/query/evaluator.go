package query

import (
	"slices"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type Evaluator struct {
	schemas    core.Schemas
	references []Reference
}

func NewEvaluator(schemas core.Schemas, references ...Reference) protocol.Evaluator[Builder] {
	return Evaluator{schemas: schemas, references: references}
}

func (e Evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Builder, error) {
	if name, ok := e.column(attribute); ok {
		leaf, err := column(name, op, value)
		return Builder{leaf}, err
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return Builder{jsonpath{compare{e.path(attribute), op, value}}}, nil
	}
	leaf, err := match(ref, attribute.Definition, op, value)
	if err != nil {
		return Builder{}, err
	}
	return e.wrap(attribute, ref, leaf), nil
}

func (e Evaluator) Present(attribute *protocol.Attribute) (Builder, error) {
	if _, ok := e.column(attribute); ok {
		return Builder{predicate{text: "TRUE"}}, nil
	}
	ref, ok := e.reference(attribute)
	if !ok {
		return Builder{jsonpath{present{e.path(attribute)}}}, nil
	}
	return e.wrap(attribute, ref, predicate{text: "TRUE"}), nil
}

func (e Evaluator) And(l, r Builder) (Builder, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return Builder{jsonpath{and{lpath.expr, rpath.expr}}}, nil
	}
	return Builder{junction{"AND", l.clause, r.clause}}, nil
}

func (e Evaluator) Or(l, r Builder) (Builder, error) {
	if lpath, rpath, ok := jsonpaths(l, r); ok {
		return Builder{jsonpath{or{lpath.expr, rpath.expr}}}, nil
	}
	return Builder{junction{"OR", l.clause, r.clause}}, nil
}

func (e Evaluator) Not(operand Builder) (Builder, error) {
	if path, ok := operand.clause.(jsonpath); ok {
		return Builder{jsonpath{not{path.expr}}}, nil
	}
	return Builder{negation{operand.clause}}, nil
}

func (e Evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Builder, error)) (Builder, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	if ref, ok := e.reference(attribute); ok {
		return Builder{reference{ref, inner.clause}}, nil
	}
	path, ok := inner.clause.(jsonpath)
	if !ok {
		return Builder{}, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return Builder{jsonpath{exists{e.path(attribute), path.expr}}}, nil
}

func (e Evaluator) wrap(attribute *protocol.Attribute, ref Reference, leaf clause) Builder {
	if attribute.Parent != nil {
		return Builder{leaf}
	}
	return Builder{reference{ref, leaf}}
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
	if attribute.Parent != nil || e.schemas.IsExtension(e.schemas.Lookup(core.SchemaURI(attribute.Path.URI))) {
		return "", false
	}
	name := strings.Join(e.keys(attribute), ".")
	_, ok := Columns[name]
	return name, ok
}

func (e Evaluator) keys(attribute *protocol.Attribute) []string {
	if top, ok := e.schemas.Resolve(core.SchemaURI(attribute.Path.URI), attribute.Path.Name, ""); ok && top != attribute.Definition {
		return []string{top.Name, attribute.Definition.Name}
	}
	return []string{attribute.Definition.Name}
}

func jsonpaths(l, r Builder) (jsonpath, jsonpath, bool) {
	lpath, lok := l.clause.(jsonpath)
	rpath, rok := r.clause.(jsonpath)
	return lpath, rpath, lok && rok
}
