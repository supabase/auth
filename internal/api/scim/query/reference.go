package query

import (
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

const ValueAttribute = "value"

type Reference interface {
	Name() string
	Columns() map[string]string
	Exists(inner string, args []any) (string, []any)
}

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := ref.Columns()[definition.Name]
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " cannot be filtered")
	}
	if definition.Name != ValueAttribute {
		return predicate{column + sign + "?", []any{strings.ToLower(text)}}, nil
	}
	return uuidPredicate(column, sign, op, text), nil
}
