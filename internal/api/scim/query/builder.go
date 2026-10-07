package query

import "github.com/gobuffalo/pop/v6"

type Builder struct {
	clause clause
}

func (b Builder) Build(q *pop.Query) *pop.Query {
	text, args := b.clause.sql()
	return q.Where(text, args...)
}
