package query

import (
	"slices"
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func Select(references []Reference, projection protocol.Projection, locations map[string]string) string {
	parts := []string{}
	for _, reference := range references {
		if projection.Returns(reference.Path()) {
			parts = append(parts, reference.part(locations))
		}
	}
	return "json_build_array(" + strings.Join(parts, ", ") + ")"
}

func Where(schemas core.Schemas, location string, references []Reference, expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(schemas, expression, NewEvaluator(schemas, location, references...))
}

func Order(schemas core.Schemas, references []Reference, request *protocol.SearchRequest) (string, []any, error) {
	if request.SortBy == "" {
		return "id", nil, nil
	}
	parent, attribute, err := request.SortAttribute(schemas)
	if err != nil {
		return "", nil, err
	}
	if resolved(references, parent, attribute) {
		return "", nil, scimerrors.ErrInvalidValue(strconv.Quote(request.SortBy) + " cannot be sorted")
	}
	direction := " ASC"
	if request.Descending() {
		direction = " DESC"
	}
	keys := []string{parent.Name}
	if parent != attribute {
		keys = append(keys, attribute.Name)
	}
	path := strings.Join(keys, ".")
	if path == "meta.created" {
		return "id" + direction, nil, nil
	}
	if column, ok := Columns[path]; ok {
		return column + direction + ", id", nil, nil
	}
	if parent.MultiValued {
		keys = []string{parent.Name, "0", attribute.Name}
	}
	for _, extension := range schemas.Extensions() {
		if extension.Attributes.Lookup(parent.Name) == parent {
			keys = append([]string{string(extension.ID)}, keys...)
		}
	}
	value, args := `resource #>> ?::text[]`, []any{keys}
	if len(keys) == 1 {
		value, args = `resource ->> `+QuoteLiteral(keys[0]), nil
	}
	if parent.MultiValued {
		value, args = `coalesce(jsonb_path_query_first(resource, ?::jsonpath) #>> '{}', `+value+`)`, []any{primary(keys), keys}
	}
	if !attribute.CaseExact {
		value = "lower(" + value + ")"
	}
	return value + ` COLLATE "C"` + direction + ", id", args, nil
}

func primary(keys []string) string {
	return path{"$", keys[:len(keys)-2]}.String() + "[*] ? (@.primary == true)." + Quote(keys[len(keys)-1])
}

func resolved(references []Reference, parent, attribute *core.Attribute) bool {
	return slices.ContainsFunc(references, func(reference Reference) bool {
		return reference.attribute == parent && reference.computed(attribute.Name)
	})
}
