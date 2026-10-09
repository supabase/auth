package query

import (
	"strconv"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
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

var prefixes = map[core.SchemaURI]map[string]string{
	core.SchemaUser:  {"userName": `lower(resource ->> 'userName') COLLATE "C"`},
	core.SchemaGroup: {"displayName": `lower(resource ->> 'displayName') COLLATE "C"`},
}

var equalities = map[core.SchemaURI]map[string]string{
	core.SchemaUser:  {"userName": prefixes[core.SchemaUser]["userName"], "externalId": `(resource ->> 'externalId') COLLATE "C"`},
	core.SchemaGroup: {"displayName": prefixes[core.SchemaGroup]["displayName"], "externalId": `(resource ->> 'externalId') COLLATE "C"`},
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
		at := models.SCIMVersionTime(text)
		if at == nil {
			return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}, nil
		}
		return predicate{"updated_at" + sign + "?", []any{*at}}, nil
	}
	return predicate{Columns[name] + sign + "?", []any{value}}, nil
}

func uuidPredicate(column, sign string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}
	}
	return predicate{column + sign + "?::uuid", []any{id.String()}}
}

func indexed(schema core.SchemaURI, name string, op filter.Operator, text string, caseExact bool) (Clause, bool) {
	if expression, ok := prefixes[schema][name]; ok && op == filter.OpStartsWith {
		return Prefix{name, expression, text}, true
	}
	expression, ok := equalities[schema][name]
	if !ok || op != filter.OpEquals {
		return nil, false
	}
	param := "lower(?)"
	if caseExact {
		param = "?"
	}
	return predicate{"(" + expression + ") IS NOT NULL AND " + expression + " = " + param, []any{text}}, true
}
