package query

import (
	"unicode/utf8"
	"uuid"
)

type Clause interface {
	SQL() (string, []any)
}

type jsonpath string

func (j jsonpath) SQL() (string, []any) {
	return "search @@ lower(?)::jsonpath", []any{string(j)}
}

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) { return p.text, p.args }

func junction(op string, l, r Clause) Clause {
	ltext, largs := l.SQL()
	rtext, rargs := r.SQL()
	return predicate{"(" + ltext + " " + op + " " + rtext + ")", append(largs, rargs...)}
}

func reference(ref Reference, provider uuid.UUID, inner Clause) Clause {
	text, args := inner.SQL()
	text, args = ref.Exists(provider, text, args)
	return predicate{text, args}
}

type Prefix struct {
	Attribute        string
	expression, text string
}

func (p Prefix) SQL() (string, []any) {
	return p.expression + " >= lower(?) AND " + p.expression + " < (lower(?) || ?)", []any{p.text, p.text, string(utf8.MaxRune)}
}
