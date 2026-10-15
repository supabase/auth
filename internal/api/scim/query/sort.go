package query

import (
	"slices"
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var sortKeyPaths = map[string]string{
	"User":  "userName",
	"Group": "displayName",
}

func (r Resource) order(request *protocol.SearchRequest) (string, []any, error) {
	if request.SortBy == "" {
		return "id", nil, nil
	}
	attribute, err := request.SortAttribute(r.schemas)
	if err != nil {
		return "", nil, err
	}
	if evaluator(r).lookup(attribute.Root()) != nil {
		return "", nil, scimerrors.ErrInvalidValue(strconv.Quote(request.SortBy) + " cannot be sorted")
	}
	direction := " ASC"
	if request.Descending() {
		direction = " DESC"
	}
	path := strings.Join(attribute.Keys(), ".")
	if path == "meta.created" {
		return "id" + direction, nil, nil
	}
	if column, ok := columns[path]; ok {
		return column + direction + ", id", nil, nil
	}
	if sortKeyPaths[r.Type] == path && !attribute.Definition.CaseExact {
		return "sort_key" + direction + ", id", nil, nil
	}
	value, args := r.sortValue(attribute)
	return value + ` COLLATE "C"` + direction + ", id", args, nil
}

func (r Resource) sortValue(attribute *protocol.Attribute) (string, []any) {
	keys := attribute.Keys()
	root := attribute.Root()
	if root.MultiValued {
		keys = slices.Insert(keys, len(keys)-1, "0")
	}
	value, args := `resource #>> ?::text[]`, []any{keys}
	if len(keys) == 1 {
		value, args = `resource ->> `+quoteLiteral(keys[0]), nil
	}
	if root.MultiValued {
		value, args = `coalesce(jsonb_path_query_first(resource, ?::jsonpath) #>> '{}', `+value+`)`, []any{path{"$", keys}.primary(), keys}
	}
	if !attribute.Definition.CaseExact {
		value = "lower(" + value + ")"
	}
	return value, args
}
