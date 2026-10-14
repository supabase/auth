package query

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func Select(references []Reference, projection protocol.Projection, locations map[string]string) string {
	return build(references, locations, func(r Reference) ([]string, bool) { return nil, projection.Returns(r.Path()) })
}

func SelectTouched(references []Reference, touched Touched, locations map[string]string) string {
	return build(references, locations, func(r Reference) ([]string, bool) {
		only, ok := touched[r.Path()]
		return only, ok
	})
}

func Where(schemas core.Schemas, location string, references []Reference, expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(schemas, expression, evaluator{schemas, location, references})
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

func Quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func References(resourceType string, schemas core.Schemas, inverses map[Edge]Edge) []Reference {
	references := []Reference{}
	for _, schema := range schemas {
		uri := core.SchemaURI("")
		if schemas.IsExtension(schema) {
			uri = schema.ID
		}
		for _, attribute := range schema.Attributes {
			targets := resourceTypes(attribute)
			if len(targets) == 0 {
				continue
			}
			ref := Reference{attribute: attribute, uri: uri, targets: targets}
			self := Edge{resourceType, ref.Path()}
			via, inverted := inverses[self]
			switch {
			case inverted:
				ref.kind, ref.via = inverse, via
			case attribute.Mutability == core.MutabilityReadOnly:
				continue
			case attribute.MultiValued:
				ref.kind, ref.nested = multi, slices.Contains(slices.Collect(maps.Values(inverses)), self)
			default:
				ref.kind = single
			}
			references = append(references, ref)
		}
	}
	return references
}

func build(references []Reference, locations map[string]string, pick func(Reference) ([]string, bool)) string {
	parts := []string{}
	for _, reference := range references {
		if only, ok := pick(reference); ok {
			reference.only = only
			parts = append(parts, reference.part(locations))
		}
	}
	return "json_build_array(" + strings.Join(parts, ", ") + ")"
}

func primary(keys []string) string {
	return path{"$", keys[:len(keys)-2]}.String() + "[*] ? (@.primary == true)." + Quote(keys[len(keys)-1])
}

func resolved(references []Reference, parent, attribute *core.Attribute) bool {
	return slices.ContainsFunc(references, func(reference Reference) bool {
		return reference.attribute == parent && reference.computed(attribute.Name)
	})
}

func literal(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return Quote(regexp.QuoteMeta(s) + suffix)
}
