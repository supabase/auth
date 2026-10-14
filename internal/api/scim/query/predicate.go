package query

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) {
	return p.text, p.args
}
