package query

import (
	"strconv"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const ValueAttribute = "value"

type Reference interface {
	Name() string
	Columns() map[string]string
	Exists(provider uuid.UUID, inner string, args []any) (string, []any)
	Extract(attribute any) ([]uuid.UUID, error)
	Link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error
	Load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error)
}

type named string

func (n named) Name() string {
	return string(n)
}

func element(id uuid.UUID, endpoint, kind string) map[string]any {
	return map[string]any{
		ValueAttribute: id.String(),
		"$ref":         endpoint + "/" + id.String(),
		"type":         kind,
	}
}

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := ref.Columns()[definition.Name]
	if !ok {
		return nil, unfilterable(ref, definition)
	}
	if definition.Name != ValueAttribute {
		return predicate{column + sign + "?", []any{strings.ToLower(text)}}, nil
	}
	return uuidPredicate(column, sign, op, text), nil
}

func unfilterable(ref Reference, definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " cannot be filtered")
}
