package query

import (
	"encoding/json"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/patch"
)

type Touched map[string][]string

func Touches(references []Reference, ops []patch.Operation) Touched {
	touched := Touched{}
	for _, op := range ops {
		if !touched.op(references, op) {
			return nil
		}
	}
	return touched
}

func (t Touched) op(references []Reference, op patch.Operation) bool {
	if op.Path == "" {
		return t.object(references, op.Value)
	}
	path, err := filter.NewPath(op.Path)
	if err != nil {
		return false
	}
	ref, known := find(references, path.URI, path.Name)
	if ref != nil {
		t.add(ref.Path(), ref.values(op, path))
	}
	return known
}

func (t Touched) object(references []Reference, raw json.RawMessage) bool {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for key, nested := range value {
		uri, names := attributes(key, nested)
		for _, name := range names {
			ref, known := find(references, uri, name)
			if !known {
				return false
			}
			if ref != nil {
				t.add(ref.Path(), nil)
			}
		}
	}
	return true
}

func attributes(key string, nested any) (string, []string) {
	if !strings.HasPrefix(strings.ToLower(key), "urn:") {
		return "", []string{key}
	}
	sub, _ := nested.(map[string]any)
	names := []string{}
	for name := range sub {
		names = append(names, name)
	}
	return key, names
}

func (t Touched) add(path string, values []string) {
	current, seen := t[path]
	switch {
	case !seen:
		t[path] = values
	case current == nil || values == nil:
		t[path] = nil
	default:
		t[path] = append(current, values...)
	}
}

func find(references []Reference, uri, name string) (*Reference, bool) {
	known := uri == ""
	for i, ref := range references {
		if !strings.EqualFold(string(ref.uri), uri) {
			continue
		}
		known = true
		if strings.EqualFold(ref.Name(), name) {
			return &references[i], true
		}
	}
	return nil, known
}

func added(op patch.Operation, path filter.Path) []string {
	var elements []struct {
		Value string `json:"value"`
	}
	if path.ValueFilter != nil || json.Unmarshal(op.Value, &elements) != nil {
		return nil
	}
	values := []string{}
	for _, element := range elements {
		values = appendUUID(values, element.Value)
	}
	return values
}

func removed(path filter.Path) []string {
	node := path.ValueFilter
	if node == nil || node.Not() || filter.Operator(node.Operator()) != filter.OpEquals || !byValue(node.AttrPath()) {
		return nil
	}
	text, _ := node.Value().(string)
	return appendUUID([]string{}, text)
}

func byValue(attribute filter.AttrPath) bool {
	return strings.EqualFold(attribute.Name, ValueAttribute) && attribute.SubAttribute == ""
}

func appendUUID(values []string, text string) []string {
	if id, err := uuid.Parse(text); err == nil {
		return append(values, id.String())
	}
	return values
}
