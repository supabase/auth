package query

import "unicode/utf8"

type prefix struct {
	attribute, expression, param, text string
}

func (p prefix) SQL() (string, []any) {
	return p.expression + " >= " + p.param + " AND " + p.expression + " < (" + p.param + " || ?)", []any{p.text, p.text, string(utf8.MaxRune)}
}
