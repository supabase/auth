package query

import (
	"strconv"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func (r Reference) leaf(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if r.kind != multi {
		return nil, r.unfilterable(definition)
	}
	if op != filter.OpPresent {
		return r.match(definition, op, value)
	}
	if definition.Name != ValueAttribute && definition.Name != r.Name() {
		return nil, r.unfilterable(definition)
	}
	return always, nil
}

func (r Reference) exists(inner Clause) Clause {
	text, args := inner.SQL()
	return predicate{"EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + text + ")", append([]any{r.Name()}, args...)}
}

func (r Reference) match(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(r.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	if definition.Name != ValueAttribute {
		return nil, r.unfilterable(definition)
	}
	text, _ := value.(string)
	return uuidPredicate("edge.target_id", op, text), nil
}

func (r Reference) unfilterable(definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(r.Name()+"."+definition.Name) + " cannot be filtered")
}
