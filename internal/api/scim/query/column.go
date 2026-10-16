package query

import (
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
)

const (
	metaLocation = "meta.location"
	lowerName    = "lower_name"
)

var columns = map[string]string{
	"id":                "id",
	"meta":              "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
	metaLocation:        "id",
	"meta.resourceType": "resource_type",
	"meta.version":      "updated_at",
}

var lowerNameSources = map[core.SchemaURI]string{
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

func usesLowerName(schema core.SchemaURI, name string, caseExact bool) bool {
	return lowerNameSources[schema] == name && !caseExact
}
