package query

import (
	"strconv"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func Where(schemas core.Schemas, provider uuid.UUID, location string, references []Reference, expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(schemas, expression, NewEvaluator(schemas, provider, location, references...))
}

func Select(references []Reference, projection protocol.Projection, locations map[string]string) string {
	parts := []string{}
	for _, reference := range references {
		if projection.Returns(projected(reference)) {
			parts = append(parts, "coalesce("+reference.Select(locations)+", '{}'::jsonb)")
		}
	}
	if len(parts) == 0 {
		return "'{}'::jsonb"
	}
	return strings.Join(parts, " || ")
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
	quoted := make([]string, len(keys))
	for i, key := range keys {
		quoted[i] = Quote(key)
	}
	return "$." + strings.Join(quoted[:len(keys)-2], ".") + "[*] ? (@.primary == true)." + quoted[len(keys)-1]
}

func resolved(references []Reference, parent, attribute *core.Attribute) bool {
	for _, reference := range references {
		if _, ok := reference.Leaf(attribute.Name, filter.OpPresent, nil); ok && reference.Name() == parent.Name {
			return true
		}
	}
	return false
}

func projected(reference Reference) string {
	if m, ok := reference.(manager); ok {
		return string(m.schema) + ":" + m.Name()
	}
	return reference.Name()
}
