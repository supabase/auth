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
		s.WriteString("." + literal(key))
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

func (p path) unsetOr(op filter.Operator, value any) string {
	last := len(p.keys) - 1
	leaf := path{"@", p.keys[last:]}
	match := "(" + leaf.compare(op, value) + " || !exists(" + leaf.String() + "))"
	if p.root == "@" {
		return match
	}
	return path{p.root, p.keys[:last]}.exists(jsonpath(match))
}

func (p path) present() string {
	return "exists(" + p.String() + ` ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`
}

func (p path) exists(inner jsonpath) string {
	return "exists(" + p.String() + "[*] ? (" + string(inner) + "))"
}

func (p path) primary() string {
	last := len(p.keys) - 1
	return path{p.root, p.keys[:last-1]}.String() + "[*] ? (@.primary == true)." + literal(p.keys[last])
}

func literal(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return literal(regexp.QuoteMeta(s) + suffix)
}
