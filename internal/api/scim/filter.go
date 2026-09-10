package scim

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

var filterColumns = map[string]string{
	"id":                "id",
	"username":          "user_name",
	"externalid":        "external_id",
	"active":            "active",
	"meta.created":      "created_at",
	"meta.lastmodified": "updated_at",
}

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

type sqlFragment struct {
	sql  string
	args []any
}

type sqlEvaluator struct {
	element string
}

func filterSQL(schemas []*core.Schema, text string) (sqlFragment, error) {
	return protocol.Filter[sqlFragment](schemas, text, &sqlEvaluator{})
}

func (f *sqlEvaluator) Compare(attribute *core.Attribute, key string, op filter.Operator, value any) (sqlFragment, error) {
	switch op {
	case filter.OpContains:
		return f.like(attribute, key, value, "%%%s%%")
	case filter.OpStartsWith:
		return f.like(attribute, key, value, "%s%%")
	case filter.OpEndsWith:
		return f.like(attribute, key, value, "%%%s")
	}

	if f.isUUIDColumn(key) {
		text, ok := value.(string)
		if !ok {
			return sqlFragment{}, protocol.ErrInvalidValue("a string value is required")
		}
		if _, err := uuid.FromString(text); err != nil {
			return sqlFragment{}, protocol.ErrInvalidValue("a valid uuid value is required")
		}
	}

	column, placeholder := f.operand(attribute, key)
	if op == filter.OpNotEquals {
		return sqlFragment{sql: column + " IS DISTINCT FROM " + placeholder, args: []any{value}}, nil
	}

	symbol, ok := comparators[op]
	if !ok {
		return sqlFragment{}, protocol.ErrInvalidFilter(fmt.Sprintf("operator %q is not supported", op))
	}
	return sqlFragment{sql: column + " " + symbol + " " + placeholder, args: []any{value}}, nil
}

func (f *sqlEvaluator) Present(attribute *core.Attribute, key string) (sqlFragment, error) {
	column, _ := f.resolveColumn(attribute, key)
	return sqlFragment{sql: column + " IS NOT NULL"}, nil
}

func (f *sqlEvaluator) And(left, right sqlFragment) (sqlFragment, error) {
	return combine(left, right, "AND"), nil
}

func (f *sqlEvaluator) Or(left, right sqlFragment) (sqlFragment, error) {
	return combine(left, right, "OR"), nil
}

func (f *sqlEvaluator) Not(operand sqlFragment) (sqlFragment, error) {
	return sqlFragment{sql: "(" + operand.sql + ") IS NOT TRUE", args: operand.args}, nil
}

func (f *sqlEvaluator) ValuePath(attribute *core.Attribute, key string, valueFilter func() (sqlFragment, error)) (sqlFragment, error) {
	previous := f.element
	f.element = "e"
	inner, err := valueFilter()
	f.element = previous
	if err != nil {
		return sqlFragment{}, err
	}

	source := "resource->'" + attribute.Name + "'"
	if column, ok := filterColumns[key]; ok {
		source = column
	}
	sql := "EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(" + source + ", '[]'::jsonb)) AS e WHERE " + inner.sql + ")"
	return sqlFragment{sql: sql, args: inner.args}, nil
}

func (f *sqlEvaluator) isUUIDColumn(key string) bool {
	if f.element != "" {
		return false
	}
	column, ok := filterColumns[key]
	return ok && uuidColumns[column]
}

func (f *sqlEvaluator) operand(attribute *core.Attribute, key string) (string, string) {
	column, promoted := f.resolveColumn(attribute, key)
	if promoted && uuidColumns[column] {
		return column, "?"
	}
	if attribute.Type == core.TypeString && !attribute.CaseExact {
		if loweredColumns[column] {
			return column, "lower(?)"
		}
		return "lower(" + column + ")", "lower(?)"
	}
	if !promoted {
		if cast := castFor(attribute.Type); cast != "" {
			return "(" + column + ")" + cast, "?"
		}
	}
	return column, "?"
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

func (f *sqlEvaluator) like(attribute *core.Attribute, key string, value any, pattern string) (sqlFragment, error) {
	text, ok := value.(string)
	if !ok {
		return sqlFragment{}, protocol.ErrInvalidValue("a string value is required")
	}
	arg := fmt.Sprintf(pattern, escapeLike(text))
	column, promoted := f.resolveColumn(attribute, key)
	if promoted && uuidColumns[column] {
		return sqlFragment{sql: "lower(" + column + "::text) LIKE lower(?) ESCAPE '\\'", args: []any{arg}}, nil
	}
	if attribute.Type == core.TypeString && !attribute.CaseExact {
		if loweredColumns[column] {
			return sqlFragment{sql: column + " LIKE lower(?) ESCAPE '\\'", args: []any{arg}}, nil
		}
		return sqlFragment{sql: "lower(" + column + ") LIKE lower(?) ESCAPE '\\'", args: []any{arg}}, nil
	}
	return sqlFragment{sql: column + " LIKE ? ESCAPE '\\'", args: []any{arg}}, nil
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

func combine(left, right sqlFragment, op string) sqlFragment {
	args := make([]any, 0, len(left.args)+len(right.args))
	args = append(args, left.args...)
	args = append(args, right.args...)
	return sqlFragment{
		sql:  "(" + left.sql + " " + op + " " + right.sql + ")",
		args: args,
	}
}
