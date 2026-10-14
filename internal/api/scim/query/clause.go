package query

type Clause interface {
	SQL() (string, []any)
}
