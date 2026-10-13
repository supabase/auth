package query

import (
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
)

type stored struct {
	named
	targets []string
}

func Stored(attribute string, targets ...string) Reference {
	return stored{named: named(attribute), targets: targets}
}

func (s stored) Targets() []string {
	return s.targets
}

func (s stored) Columns() map[string]string {
	return map[string]string{
		ValueAttribute: "edge.target_id",
		"type":         "lower(target.resource_type)",
	}
}

func (s stored) Exists(_ uuid.UUID, inner string, args []any) (string, []any) {
	return "EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + inner + ")", append([]any{s.Name()}, args...)
}

func (s stored) Select(locations map[string]string) string {
	return `(SELECT json_build_object(` + QuoteLiteral(s.Name()) + `, json_agg(json_build_object('value', target_id, '$ref', ` + endpoint(locations, "target_type") + ` || target_id, 'type', target_type))) FROM scim_resource_references WHERE source_id = scim_resources.id AND attribute = ` + QuoteLiteral(s.Name()) + `)`
}

func (s stored) Leaf(string, filter.Operator, any) (Clause, bool) {
	return nil, false
}

func (s stored) Strip(document core.Object) {
	document.Remove(s.Name())
}
