package scim

import (
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
)

var loweredColumns = map[string]bool{
	"user_name": true,
}

var uuidColumns = map[string]bool{
	"id": true,
}

var comparators = map[filter.Operator]string{
	filter.OpEquals:            "=",
	filter.OpGreaterThan:       ">",
	filter.OpGreaterThanEquals: ">=",
	filter.OpLessThan:          "<",
	filter.OpLessThanEquals:    "<=",
}

var likePatterns = map[filter.Operator]string{
	filter.OpContains:   "%%%s%%",
	filter.OpStartsWith: "%s%%",
	filter.OpEndsWith:   "%%%s",
}

func (f *sqlEvaluator) resolveColumn(attribute *core.Attribute, key string) (string, bool) {
	if f.element != "" {
		return f.element + "->>'" + attribute.Name + "'", false
	}
	if column, ok := filterColumns[key]; ok {
		return column, true
	}
	return "resource->>'" + attribute.Name + "'", false
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func castFor(attributeType core.AttributeType) string {
	switch attributeType {
	case core.TypeDateTime:
		return "::timestamptz"
	case core.TypeInteger, core.TypeDecimal:
		return "::numeric"
	case core.TypeBoolean:
		return "::boolean"
	}
	return ""
}

func loweredExpr(column string) string {
	if loweredColumns[column] {
		return column
	}
	return "lower(" + column + ")"
}

func castExpr(column string, promoted bool, attributeType core.AttributeType) (string, bool) {
	if promoted {
		return "", false
	}
	cast := castFor(attributeType)
	if cast == "" {
		return "", false
	}
	return "(" + column + ")" + cast, true
}

func combine(left, right sqlFragment, op string) sqlFragment {
	args := make([]any, 0, len(left.args)+len(right.args))
	args = append(args, left.args...)
	args = append(args, right.args...)
	return sqlFragment{
		sql:  "(" + left.sql + " " + op + " " + right.sql + ")",
		args: args,
	}
}
