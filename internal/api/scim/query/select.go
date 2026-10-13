package query

import (
	"maps"
	"slices"
	"strings"
)

func (r Reference) Select(locations map[string]string) string {
	switch r.kind {
	case multi:
		return r.edgeSelect(locations)
	case inverse:
		return r.inverseSelect(locations)
	}
	return r.singleSelect(locations)
}

func (r Reference) part(locations map[string]string) string {
	if r.uri == "" {
		return "json_build_object(" + QuoteLiteral(r.Name()) + ", " + r.Select(locations) + ")"
	}
	return "(SELECT json_build_object(" + QuoteLiteral(string(r.uri)) + ", json_build_object(" + QuoteLiteral(r.Name()) + ", v)) FROM (SELECT " + r.Select(locations) + ") x(v) WHERE v IS NOT NULL)"
}

func literals(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = QuoteLiteral(value)
	}
	return strings.Join(quoted, ", ")
}

func endpoint(locations map[string]string, kind string) string {
	var s strings.Builder
	s.WriteString("CASE " + kind)
	for _, name := range slices.Sorted(maps.Keys(locations)) {
		s.WriteString(" WHEN " + QuoteLiteral(name) + " THEN " + QuoteLiteral(locations[name]+"/"))
	}
	s.WriteString(" END")
	return s.String()
}
