package query

import "uuid"

type Clause interface {
	SQL() (string, []any)
}

type jsonpath struct{ expr expr }

func (j jsonpath) SQL() (string, []any) {
	return "search @@ ?::jsonpath", []any{j.expr.String()}
}

type exact struct{ expr expr }

func (e exact) SQL() (string, []any) {
	return "resource @@ ?::jsonpath", []any{e.expr.String()}
}

type junction struct {
	op   string
	l, r Clause
}

func (j junction) SQL() (string, []any) {
	l, largs := j.l.SQL()
	r, rargs := j.r.SQL()
	return "(" + l + " " + j.op + " " + r + ")", append(largs, rargs...)
}

type negation struct{ x Clause }

func (n negation) SQL() (string, []any) {
	x, args := n.x.SQL()
	return "NOT (" + x + ")", args
}

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) { return p.text, p.args }

type reference struct {
	ref      Reference
	provider uuid.UUID
	inner    Clause
}

func (r reference) SQL() (string, []any) {
	inner, args := r.inner.SQL()
	return r.ref.Exists(r.provider, inner, args)
}

type Prefix struct {
	Attribute          string
	expression, lo, hi string
}

func (p Prefix) SQL() (string, []any) {
	return p.expression + " >= ? AND " + p.expression + " < ?", []any{p.lo, p.hi}
}
