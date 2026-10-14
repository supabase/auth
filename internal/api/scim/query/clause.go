package query

import "unicode/utf8"

type Clause interface {
	SQL() (string, []any)
}

var (
	always Clause = predicate{text: "TRUE"}
	never  Clause = predicate{text: "FALSE"}
)

func boolean(value bool) Clause {
	if value {
		return always
	}
	return never
}

func and(l, r Clause) Clause {
	return combine(l, r, " && ", "AND")
}

func or(l, r Clause) Clause {
	return combine(l, r, " || ", "OR")
}

func not(operand Clause) Clause {
	if path, ok := operand.(jsonpath); ok {
		return "!(" + path + ")"
	}
	text, args := operand.SQL()
	return predicate{"NOT (" + text + ")", args}
}

func combine(l, r Clause, logical, op string) Clause {
	lpath, lok := l.(jsonpath)
	rpath, rok := r.(jsonpath)
	if lok && rok {
		return "(" + lpath + jsonpath(logical) + rpath + ")"
	}
	ltext, largs := l.SQL()
	rtext, rargs := r.SQL()
	return predicate{"(" + ltext + " " + op + " " + rtext + ")", append(largs, rargs...)}
}

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) {
	return p.text, p.args
}

type jsonpath string

func (j jsonpath) SQL() (string, []any) {
	return "search @@ lower(?)::jsonpath", []any{string(j)}
}

type prefix struct {
	attribute, expression, param, text string
}

func (p prefix) SQL() (string, []any) {
	return p.expression + " >= " + p.param + " AND " + p.expression + " < (" + p.param + " || ?)", []any{p.text, p.text, string(utf8.MaxRune)}
}
