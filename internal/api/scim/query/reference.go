package query

import (
	"fmt"
	"strconv"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/store"
)

const edgeExists = `EXISTS (
  SELECT 1
  FROM scim_resource_references edge
  WHERE edge.source_id = scim_resources.id
    AND edge.attribute = ?
    AND %s
)`

const inverseSubquery = `(
  SELECT jsonb_agg(jsonb_build_object('value', id, 'type', type) ORDER BY id)
  FROM (
    SELECT DISTINCT ON (id) id, type
    FROM (
      WITH RECURSIVE up(id, type) AS (
        SELECT source_id, 'direct'
        FROM scim_resource_references
        WHERE target_id = scim_resources.id AND attribute = %[1]s
        UNION
        SELECT edge.source_id, 'indirect'
        FROM scim_resource_references edge
        JOIN up ON edge.target_id = up.id
        WHERE edge.attribute = %[1]s
      )
      SELECT id, type FROM up
    ) walked
    ORDER BY id, type
  ) deduped
)`

const memberSubquery = `(
  SELECT jsonb_agg(jsonb_build_object('value', target_id, 'type', target_type) ORDER BY target_id)
  FROM scim_resource_references
  WHERE source_id = scim_resources.id
    AND attribute = %s
)`

type Reference struct {
	store.Reference
}

func (r Reference) Pair() string {
	if r.Inverse() {
		return quoteLiteral(r.Name) + ", " + fmt.Sprintf(inverseSubquery, quoteLiteral(r.InverseOf))
	}
	return quoteLiteral(r.Name) + ", " + fmt.Sprintf(memberSubquery, quoteLiteral(r.Name))
}

func (r Reference) leaf(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if r.Inverse() {
		return nil, r.unfilterable(definition)
	}
	if op != filter.OpPresent {
		return r.match(definition, op, value)
	}
	if definition.Name != store.ValueAttribute && definition.Name != r.Name {
		return nil, r.unfilterable(definition)
	}
	return always, nil
}

func (r Reference) exists(inner Clause) Clause {
	text, args := inner.SQL()
	return predicate{fmt.Sprintf(edgeExists, text), append([]any{r.Name}, args...)}
}

func (r Reference) match(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(r.Name+"."+definition.Name) + " supports only eq and ne")
	}
	text, _ := value.(string)
	switch definition.Name {
	case store.ValueAttribute:
		return uuidPredicate("edge.target_id", op, text), nil
	case "type":
		return predicate{"lower(edge.target_type)" + comparisons[op] + "?", []any{definition.Fold(text)}}, nil
	}
	return nil, r.unfilterable(definition)
}

func (r Reference) unfilterable(definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(r.Name+"."+definition.Name) + " cannot be filtered")
}
