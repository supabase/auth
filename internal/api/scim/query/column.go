package query

import (
	"slices"
	"strconv"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var Columns = map[string]string{
	"id":                "id",
	"meta":              "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
	"meta.location":     "id",
	"meta.resourceType": "resource_type",
	"meta.version":      "updated_at",
}

var indexes = map[core.SchemaURI][]string{
	core.SchemaUser:  {"userName", "externalId"},
	core.SchemaGroup: {"displayName", "externalId"},
}

var comparisons = map[filter.Operator]string{
	filter.OpEquals:            " = ",
	filter.OpNotEquals:         " <> ",
	filter.OpGreaterThan:       " > ",
	filter.OpGreaterThanEquals: " >= ",
	filter.OpLessThan:          " < ",
	filter.OpLessThanEquals:    " <= ",
}

func column(name, location string, op filter.Operator, value any) (Clause, error) {
	sign, ok := comparisons[op]
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(name) + " supports only eq, ne, gt, ge, lt and le")
	}
	text, _ := value.(string)
	switch name {
	case "id":
		return uuidPredicate("id", sign, op, text), nil
	case "meta.location":
		id, found := strings.CutPrefix(text, location+"/")
		if !found {
			id = ""
		}
		return uuidPredicate("id", sign, op, id), nil
	case "meta.version":
		at := VersionTime(text)
		if at == nil {
			return boolean(op == filter.OpNotEquals), nil
		}
		return predicate{"updated_at" + sign + "?", []any{*at}}, nil
	}
	return predicate{Columns[name] + sign + "?", []any{value}}, nil
}

func uuidPredicate(column, sign string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return boolean(op == filter.OpNotEquals)
	}
	return predicate{column + sign + "?::uuid", []any{id.String()}}
}

func indexed(schema core.SchemaURI, name string, op filter.Operator, text string, caseExact bool) (Clause, bool) {
	sign, ranged := comparisons[op]
	if !slices.Contains(indexes[schema], name) || op == filter.OpNotEquals || !ranged && op != filter.OpStartsWith {
		return nil, false
	}
	expression, param := expression(name, caseExact)
	if op == filter.OpStartsWith {
		return prefix{name, expression, param, text}, true
	}
	return predicate{"(" + expression + ") IS NOT NULL AND " + expression + sign + param, []any{text}}, true
}

func expression(name string, caseExact bool) (string, string) {
	value := "resource ->> " + QuoteLiteral(name)
	if caseExact {
		return "(" + value + `) COLLATE "C"`, "?"
	}
	return "lower(" + value + `) COLLATE "C"`, "lower(?)"
}
