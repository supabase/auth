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
	return p.render(strings.ToLower)
}

func (p path) render(fold func(string) string) string {
	var s strings.Builder
	s.WriteString(p.root)
	for _, key := range p.keys {
		s.WriteString("." + Quote(fold(key)))
	}
	return s.String()
}

type compare struct {
	path  path
	op    filter.Operator
	value any
	exact bool
}

func (c compare) String() string {
	fold := strings.ToLower
	if c.exact {
		fold = func(s string) string { return s }
	}
	path := c.path.render(fold)
	switch c.op {
	case filter.OpStartsWith:
		return path + " starts with " + literal(c.value, fold)
	case filter.OpContains:
		return path + " like_regex " + pattern(c.value, "", fold)
	case filter.OpEndsWith:
		return path + " like_regex " + pattern(c.value, "$", fold)
	}
	return path + " " + operators[c.op] + " " + literal(c.value, fold)
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

func literal(value any, fold func(string) string) string {
	if text, ok := value.(string); ok {
		return Quote(fold(text))
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string, fold func(string) string) string {
	s, _ := value.(string)
	return Quote(regexp.QuoteMeta(fold(s)) + suffix)
}

func Quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
