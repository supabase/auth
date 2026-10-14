package query

import (
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func (r Resource) order(request *protocol.SearchRequest) (string, []any, error) {
	if request.SortBy == "" {
		return "id", nil, nil
	}
	parent, attribute, err := request.SortAttribute(r.schemas)
	if err != nil {
		return "", nil, err
	}
	if evaluator(r).lookup(parent) != nil {
		return "", nil, scimerrors.ErrInvalidValue(strconv.Quote(request.SortBy) + " cannot be sorted")
	}
	direction := " ASC"
	if request.Descending() {
		direction = " DESC"
	}
	path := strings.Join(sortKeys(parent, attribute), ".")
	if path == "meta.created" {
		return "id" + direction, nil, nil
	}
	if column, ok := columns[path]; ok {
		return column + direction + ", id", nil, nil
	}
	value, args := r.sortValue(parent, attribute)
	return value + ` COLLATE "C"` + direction + ", id", args, nil
}

func sortKeys(parent, attribute *core.Attribute) []string {
	if parent == attribute {
		return []string{parent.Name}
	}
	return []string{parent.Name, attribute.Name}
}

func (r Resource) sortValue(parent, attribute *core.Attribute) (string, []any) {
	keys := sortKeys(parent, attribute)
	if parent.MultiValued {
		keys = []string{parent.Name, "0", attribute.Name}
	}
	for _, extension := range r.schemas.Extensions() {
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
	return value, args
}

func primary(keys []string) string {
	return path{"$", keys[:len(keys)-2]}.String() + "[*] ? (@.primary == true)." + literal(keys[len(keys)-1])
}
