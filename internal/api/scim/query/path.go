package query

import (
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

func (p path) compare(op filter.Operator, value any) string {
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

func (p path) present() string {
	return "exists(" + p.String() + ` ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`
}

func (p path) exists(inner jsonpath) string {
	return "exists(" + p.String() + "[*] ? (" + string(inner) + "))"
}
