package query

import (
	"slices"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
)

const metaLocation = "meta.location"

var columns = map[string]string{
	"id":                "id",
	"meta":              "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
	metaLocation:        "id",
	"meta.resourceType": "resource_type",
	"meta.version":      "updated_at",
}

var indexes = map[core.SchemaURI][]string{
	core.SchemaUser: {"userName"},
}

var lowerNames = map[core.SchemaURI]string{
	core.SchemaUser:  "userName",
	core.SchemaGroup: "displayName",
}

var comparisons = map[filter.Operator]string{
	filter.OpEquals:            " = ",
	filter.OpNotEquals:         " <> ",
	filter.OpGreaterThan:       " > ",
	filter.OpGreaterThanEquals: " >= ",
	filter.OpLessThan:          " < ",
	filter.OpLessThanEquals:    " <= ",
}

func uuidPredicate(column string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return boolean(op == filter.OpNotEquals)
	}
	return predicate{column + comparisons[op] + "?::uuid", []any{id.String()}}
}

func indexed(schema core.SchemaURI, name string, op filter.Operator, text string, caseExact bool) (Clause, bool) {
	sign, ranged := comparisons[op]
	if !slices.Contains(indexes[schema], name) || op == filter.OpNotEquals || !ranged && op != filter.OpStartsWith {
		return nil, false
	}
	expression, param := expression(name, caseExact)
	if op == filter.OpStartsWith {
		return prefix{expression, param, text}, true
	}
	return predicate{"(" + expression + ") IS NOT NULL AND " + expression + sign + param, []any{text}}, true
}

func expression(name string, caseExact bool) (string, string) {
	value := "resource ->> " + quoteLiteral(name)
	if caseExact {
		return "(" + value + `) COLLATE "C"`, "?"
	}
	return "lower(" + value + `) COLLATE "C"`, "lower(?)"
}
