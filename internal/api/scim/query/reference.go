package query

import (
	"maps"
	"slices"
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
	Select(locations map[string]string) string
}

type named string

func (n named) Name() string {
	return string(n)
}

func endpoint(locations map[string]string, kind string) string {
	var s strings.Builder
	s.WriteString("CASE " + kind)
	for _, name := range slices.Sorted(maps.Keys(locations)) {
		s.WriteString(" WHEN " + models.QuoteLiteral(name) + " THEN " + models.QuoteLiteral(locations[name]+"/"))
	}
	s.WriteString(" END")
	return s.String()
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
