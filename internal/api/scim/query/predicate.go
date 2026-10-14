package query

type predicate struct {
	text string
	args []any
}

func (p predicate) SQL() (string, []any) {
	return p.text, p.args
}

func junction(op string, l, r Clause) Clause {
	ltext, largs := l.SQL()
	rtext, rargs := r.SQL()
	return predicate{"(" + ltext + " " + op + " " + rtext + ")", append(largs, rargs...)}
}
