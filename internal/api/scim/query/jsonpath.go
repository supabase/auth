package query

type jsonpath string

func (j jsonpath) SQL() (string, []any) {
	return "search @@ lower(?)::jsonpath", []any{string(j)}
}
