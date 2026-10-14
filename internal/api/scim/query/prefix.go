package query

import "unicode/utf8"

type Prefix struct {
	Attribute               string
	expression, param, text string
}

func (p Prefix) SQL() (string, []any) {
	return p.expression + " >= " + p.param + " AND " + p.expression + " < (" + p.param + " || ?)", []any{p.text, p.text, string(utf8.MaxRune)}
}
