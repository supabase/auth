package query

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/supabase-community/scim-go/pkg/filter"
)

var operators = map[filter.Operator]string{
	filter.OpEquals:            "==",
	filter.OpNotEquals:         "!=",
	filter.OpGreaterThan:       ">",
	filter.OpGreaterThanEquals: ">=",
	filter.OpLessThan:          "<",
	filter.OpLessThanEquals:    "<=",
}

type path struct {
	root string
	keys []string
}

func (p path) String() string {
	var s strings.Builder
	s.WriteString(p.root)
	for _, key := range p.keys {
		s.WriteString("." + Quote(key))
	}
	return s.String()
}

func Quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func compare(p path, op filter.Operator, value any) string {
	path := p.String()
	switch op {
	case filter.OpStartsWith:
		return path + " starts with " + literal(value)
	case filter.OpContains:
		return path + " like_regex " + pattern(value, "")
	case filter.OpEndsWith:
		return path + " like_regex " + pattern(value, "$")
	}
	return path + " " + operators[op] + " " + literal(value)
}

func present(p path) string {
	return "exists(" + p.String() + ` ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`
}

func exists(p path, inner jsonpath) string {
	return "exists(" + p.String() + "[*] ? (" + string(inner) + "))"
}

func literal(value any) string {
	if text, ok := value.(string); ok {
		return Quote(text)
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return Quote(regexp.QuoteMeta(s) + suffix)
}
