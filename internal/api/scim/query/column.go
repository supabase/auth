package query

import (
	"strconv"
	"strings"
	"unicode/utf8"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

var Columns = map[string]string{
	"id":                "id",
	"meta.created":      "created_at",
	"meta.lastModified": "updated_at",
	"meta.location":     "id",
	"meta.resourceType": "resource_type",
	"meta.version":      "updated_at",
}

var prefixes = map[string]string{
	"userName": `lower(resource ->> 'userName') COLLATE "C"`,
}

var equalities = map[string]string{
	"userName":   prefixes["userName"],
	"externalId": `(resource ->> 'externalId') COLLATE "C"`,
}

var comparisons = map[filter.Operator]string{
	filter.OpEquals:            " = ",
	filter.OpNotEquals:         " <> ",
	filter.OpGreaterThan:       " > ",
	filter.OpGreaterThanEquals: " >= ",
	filter.OpLessThan:          " < ",
	filter.OpLessThanEquals:    " <= ",
}

func column(name, location string, op filter.Operator, value any) (Clause, error) {
	sign, ok := comparisons[op]
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(name) + " supports only eq, ne, gt, ge, lt and le")
	}
	text, _ := value.(string)
	switch name {
	case "id":
		return uuidPredicate("id", sign, op, text), nil
	case "meta.location":
		id, found := strings.CutPrefix(text, location+"/")
		if !found {
			id = ""
		}
		return uuidPredicate("id", sign, op, id), nil
	case "meta.version":
		at := models.SCIMVersionTime(text)
		if at == nil {
			return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}, nil
		}
		return predicate{"updated_at" + sign + "?", []any{*at}}, nil
	}
	return predicate{Columns[name] + sign + "?", []any{value}}, nil
}

func uuidPredicate(column, sign string, op filter.Operator, text string) Clause {
	id, err := uuid.Parse(text)
	if err != nil {
		return predicate{text: strconv.FormatBool(op == filter.OpNotEquals)}
	}
	return predicate{column + sign + "?::uuid", []any{id.String()}}
}

func indexed(name string, op filter.Operator, text string) (Clause, bool) {
	if op == filter.OpStartsWith {
		return prefix(name, text)
	}
	expression, ok := equalities[name]
	if !ok || op != filter.OpEquals {
		return nil, false
	}
	return predicate{"(" + expression + ") IS NOT NULL AND " + expression + " = ?", []any{text}}, true
}

func prefix(name, text string) (Clause, bool) {
	expression, ok := prefixes[name]
	last, size := utf8.DecodeLastRuneInString(text)
	if !ok || text == "" || !utf8.ValidRune(last+1) {
		return nil, false
	}
	return Prefix{name, expression, text, text[:len(text)-size] + string(last+1)}, true
}
