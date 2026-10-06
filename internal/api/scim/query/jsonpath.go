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

type expr interface {
	String() string
}

type path struct {
	root string
	keys []string
}

func (p path) String() string {
	var s strings.Builder
	s.WriteString(p.root)
	for _, key := range p.keys {
		s.WriteString("." + quote(strings.ToLower(key)))
	}
	return s.String()
}

type compare struct {
	path  path
	op    filter.Operator
	value any
}

func (c compare) String() string {
	switch c.op {
	case filter.OpStartsWith:
		return c.path.String() + " starts with " + literal(c.value)
	case filter.OpContains:
		return c.path.String() + " like_regex " + pattern(c.value, "")
	case filter.OpEndsWith:
		return c.path.String() + " like_regex " + pattern(c.value, "$")
	}
	return c.path.String() + " " + operators[c.op] + " " + literal(c.value)
}

type present struct{ path path }

func (p present) String() string {
	return "exists(" + p.path.String() + ` ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`
}

type and struct{ l, r expr }

func (a and) String() string { return "(" + a.l.String() + " && " + a.r.String() + ")" }

type or struct{ l, r expr }

func (o or) String() string { return "(" + o.l.String() + " || " + o.r.String() + ")" }

type not struct{ x expr }

func (n not) String() string { return "!(" + n.x.String() + ")" }

type exists struct {
	path  path
	inner expr
}

func (e exists) String() string {
	return "exists(" + e.path.String() + "[*] ? (" + e.inner.String() + "))"
}

func literal(value any) string {
	if text, ok := value.(string); ok {
		return quote(strings.ToLower(text))
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return quote(regexp.QuoteMeta(strings.ToLower(s)) + suffix)
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
