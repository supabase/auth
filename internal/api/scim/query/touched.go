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
		if op.Path == "" {
			if !touched.keys(references, op.Value) {
				return nil
			}
			continue
		}
		path, err := filter.NewPath(op.Path)
		if err != nil {
			return nil
		}
		ref, known := find(references, path.URI, path.Name)
		if !known {
			return nil
		}
		if ref != nil {
			touched.add(ref.Path(), ref.values(op, path))
		}
	}
	return touched
}

func (t Touched) Has(reference Reference) bool {
	_, ok := t[reference.Path()]
	return ok
}

func (t Touched) Values(reference Reference) []string {
	return t[reference.Path()]
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

func (t Touched) keys(references []Reference, raw json.RawMessage) bool {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for key, nested := range value {
		names := []string{key}
		uri := ""
		if strings.HasPrefix(strings.ToLower(key), "urn:") {
			sub, _ := nested.(map[string]any)
			uri, names = key, nil
			for name := range sub {
				names = append(names, name)
			}
		}
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

func find(references []Reference, uri, name string) (*Reference, bool) {
	known := uri == ""
	for i, ref := range references {
		if uri != "" && strings.EqualFold(string(ref.uri), uri) {
			known = true
		}
		if strings.EqualFold(string(ref.uri), uri) && strings.EqualFold(ref.Name(), name) {
			return &references[i], true
		}
	}
	return nil, known
}

func (r Reference) values(op patch.Operation, path filter.Path) []string {
	if r.kind != multi || r.attribute.Required || path.SubAttribute != "" {
		return nil
	}
	switch patch.Op(strings.ToLower(string(op.Op))) {
	case patch.OpAdd:
		if path.ValueFilter != nil {
			return nil
		}
		var elements []struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(op.Value, &elements) != nil {
			return nil
		}
		values := []string{}
		for _, element := range elements {
			values = appendUUID(values, element.Value)
		}
		return values
	case patch.OpRemove:
		node := path.ValueFilter
		if node == nil || node.Not() || filter.Operator(node.Operator()) != filter.OpEquals || !strings.EqualFold(node.AttrPath().Name, ValueAttribute) || node.AttrPath().SubAttribute != "" {
			return nil
		}
		text, _ := node.Value().(string)
		return appendUUID([]string{}, text)
	}
	return nil
}

func appendUUID(values []string, text string) []string {
	if id, err := uuid.Parse(text); err == nil {
		return append(values, id.String())
	}
	return values
}
