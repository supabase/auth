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

func lowerNameOf(schema *core.Schema) *core.Attribute {
	name := schema.Attributes.Lookup(lowerNameSources[schema.ID])
	if name == nil || name.CaseExact {
		return nil
	}
	return name
}

func uuidPredicate(column string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return boolean(op == filter.OpNotEquals)
	}
	return predicate{column + comparisons[op] + "?::uuid", []any{id.String()}}
}
