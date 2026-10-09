package query

import "uuid"

type Clause interface {
	SQL() (string, []any)
}

type jsonpath string

func (j jsonpath) SQL() (string, []any) {
	return "search @@ ?::jsonpath", []any{string(j)}
}

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) { return p.text, p.args }

func exact(path string) Clause {
	return predicate{"resource @@ ?::jsonpath", []any{path}}
}

func junction(op string, l, r Clause) Clause {
	ltext, largs := l.SQL()
	rtext, rargs := r.SQL()
	return predicate{"(" + ltext + " " + op + " " + rtext + ")", append(largs, rargs...)}
}

func negation(x Clause) Clause {
	text, args := x.SQL()
	return predicate{"NOT (" + text + ")", args}
}

func reference(ref Reference, provider uuid.UUID, inner Clause) Clause {
	text, args := inner.SQL()
	text, args = ref.Exists(provider, text, args)
	return predicate{text, args}
}

type Prefix struct {
	Attribute          string
	expression, lo, hi string
}

func (p Prefix) SQL() (string, []any) {
	return p.expression + " >= ? AND " + p.expression + " < ?", []any{p.lo, p.hi}
}
