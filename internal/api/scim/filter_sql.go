package scim

import (
	"strings"

	"github.com/supabase/auth/internal/api/scim/protocol"
)

// compileUserFilter turns a parsed filter into a WHERE fragment over the flat
// columns of scim_users and the parameters it binds. Every value reaches SQL as
// a placeholder; a filter this store cannot serve -- a valuePath, an attribute
// with no column, or an operator outside the pushed-down subset -- is
// ErrInvalidFilter, the 400 of RFC 7644, Section 3.4.2.2.
func compileUserFilter(filter protocol.Filter) (string, []any, error) {
	var args []any
	sql, err := compileFilterNode(filter, &args)
	if err != nil {
		return "", nil, err
	}
	return sql, args, nil
}

func compileFilterNode(filter protocol.Filter, args *[]any) (string, error) {
	switch f := filter.(type) {
	case *protocol.LogicalExpr:
		return compileLogical(f, args)
	case *protocol.NotExpr:
		inner, err := compileFilterNode(f.Inner, args)
		if err != nil {
			return "", err
		}
		return "NOT (" + inner + ")", nil
	case *protocol.AttrExpr:
		return compileAttrExpr(f, args)
	case *protocol.ValuePath:
		return "", protocol.ErrInvalidFilter("value-path filters are not supported")
	default:
		return "", protocol.ErrInvalidFilter("unsupported filter expression")
	}
}

func compileLogical(f *protocol.LogicalExpr, args *[]any) (string, error) {
	left, err := compileFilterNode(f.Left, args)
	if err != nil {
		return "", err
	}
	right, err := compileFilterNode(f.Right, args)
	if err != nil {
		return "", err
	}

	op := "AND"
	if f.Op == protocol.LogicalOr {
		op = "OR"
	}
	return "(" + left + " " + op + " " + right + ")", nil
}

func compileAttrExpr(f *protocol.AttrExpr, args *[]any) (string, error) {
	attr, err := resolveUserFilterAttr(f.Path)
	if err != nil {
		return "", err
	}
	if err := checkOp(attr, f.Op); err != nil {
		return "", err
	}

	if f.Op == protocol.OpPresent {
		return attr.column + " IS NOT NULL", nil
	}

	lhs, rhs := foldedOperands(attr)

	switch f.Op {
	case protocol.OpEqual, protocol.OpNotEqual:
		arg, err := scalarArg(attr, f.Value)
		if err != nil {
			return "", err
		}
		*args = append(*args, arg)

		cmp := "="
		if f.Op == protocol.OpNotEqual {
			cmp = "<>"
		}
		return lhs + " " + cmp + " " + rhs, nil

	case protocol.OpContains, protocol.OpStartsWith, protocol.OpEndsWith:
		s, err := stringValue(f.Value)
		if err != nil {
			return "", err
		}
		*args = append(*args, likePattern(f.Op, s))
		return lhs + " LIKE " + rhs, nil
	}

	return "", protocol.ErrInvalidFilter("unsupported filter operator")
}

// foldedOperands is the column and the placeholder a comparison compares, folded
// to lower case for a string attribute that is not caseExact -- which is what
// makes "userName eq" case insensitive, agreeing with the lower(user_name) the
// index and the memory store both use.
func foldedOperands(attr filterAttr) (lhs, rhs string) {
	if attr.kind == filterString && !attr.caseExact {
		return "lower(" + attr.column + ")", "lower(?)"
	}
	return attr.column, "?"
}

func scalarArg(attr filterAttr, v protocol.Value) (any, error) {
	switch attr.kind {
	case filterBool:
		return boolValue(v)
	case filterTime:
		return timeValue(v)
	case filterUUID:
		return uuidValue(v)
	default:
		return stringValue(v)
	}
}

// likePattern is the LIKE pattern a substring operator compares against, with
// the value's own LIKE metacharacters escaped so that a userName holding a
// percent sign is matched literally rather than as a wildcard.
func likePattern(op protocol.CompareOp, value string) string {
	escaped := likeEscaper.Replace(value)
	switch op {
	case protocol.OpStartsWith:
		return escaped + "%"
	case protocol.OpEndsWith:
		return "%" + escaped
	default:
		return "%" + escaped + "%"
	}
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
