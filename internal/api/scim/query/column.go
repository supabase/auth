package query

import (
	"strconv"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var Columns = map[string]string{
	"id":                "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
}

var comparisons = map[filter.Operator]string{
	filter.OpEquals:            " = ",
	filter.OpNotEquals:         " <> ",
	filter.OpGreaterThan:       " > ",
	filter.OpGreaterThanEquals: " >= ",
	filter.OpLessThan:          " < ",
	filter.OpLessThanEquals:    " <= ",
}

func column(name string, op filter.Operator, value any) (Clause, error) {
	sign, ok := comparisons[op]
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(name) + " supports only eq, ne, gt, ge, lt and le")
	}
	if name != "id" {
		return predicate{Columns[name] + sign + "?", []any{value}}, nil
	}
	text, _ := value.(string)
	return uuidPredicate("id", sign, op, text), nil
}

func uuidPredicate(column, sign string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}
	}
	return predicate{column + sign + "?::uuid", []any{id.String()}}
}
