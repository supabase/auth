package scim

import (
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

// filterUsers keeps the Users a filter matches. It rejects a filter the store
// cannot serve by compiling it first, so the memory store turns away exactly
// what the Postgres store does -- including against an empty tenant, where no
// User would otherwise be evaluated to surface the error.
func filterUsers(users []*core.User, filter protocol.Filter) ([]*core.User, error) {
	if _, _, err := compileUserFilter(filter); err != nil {
		return nil, err
	}

	kept := make([]*core.User, 0, len(users))
	for _, u := range users {
		ok, err := matchUserFilter(u, filter)
		if err != nil {
			return nil, err
		}
		if ok {
			kept = append(kept, u)
		}
	}
	return kept, nil
}

// matchUserFilter evaluates a parsed filter against a User the way
// compileUserFilter evaluates it in SQL, so the memory store and the Postgres
// store agree on which resources a filter selects. A filter neither store can
// serve is ErrInvalidFilter, returned whether or not any User matches, so that
// an unfilterable attribute is a 400 rather than an empty page.
//
// Both sides of a logExp are evaluated even when the first settles the result,
// so a structural error in either half is reported as the compiler would report
// it rather than hidden by short-circuiting.
func matchUserFilter(u *core.User, filter protocol.Filter) (bool, error) {
	switch f := filter.(type) {
	case *protocol.LogicalExpr:
		left, err := matchUserFilter(u, f.Left)
		if err != nil {
			return false, err
		}
		right, err := matchUserFilter(u, f.Right)
		if err != nil {
			return false, err
		}
		if f.Op == protocol.LogicalOr {
			return left || right, nil
		}
		return left && right, nil

	case *protocol.NotExpr:
		inner, err := matchUserFilter(u, f.Inner)
		if err != nil {
			return false, err
		}
		return !inner, nil

	case *protocol.AttrExpr:
		return matchAttrExpr(u, f)

	case *protocol.ValuePath:
		return false, protocol.ErrInvalidFilter("value-path filters are not supported")

	default:
		return false, protocol.ErrInvalidFilter("unsupported filter expression")
	}
}

func matchAttrExpr(u *core.User, f *protocol.AttrExpr) (bool, error) {
	attr, err := resolveUserFilterAttr(f.Path)
	if err != nil {
		return false, err
	}
	if err := checkOp(attr, f.Op); err != nil {
		return false, err
	}

	raw, present := attr.valueOf(u)

	if f.Op == protocol.OpPresent {
		return present, nil
	}

	// The value is coerced before presence is consulted, so a mistyped compValue
	// is ErrInvalidFilter even against an absent attribute -- as it is in SQL,
	// where compilation fails before a row is ever read.
	want, err := coerceValue(attr, f.Value)
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}

	switch attr.kind {
	case filterBool:
		got, _ := raw.(bool)
		w, _ := want.(bool)
		return matchesEquality(f.Op, got == w), nil

	case filterTime:
		got, _ := raw.(time.Time)
		w, _ := want.(time.Time)
		return matchesEquality(f.Op, got.Equal(w)), nil

	case filterUUID:
		got, _ := raw.(string)
		w, _ := want.(string)
		return matchesEquality(f.Op, strings.EqualFold(got, w)), nil

	default:
		got, _ := raw.(string)
		w, _ := want.(string)
		return compareString(f.Op, got, w, attr.caseExact), nil
	}
}

// matchesEquality reads an equality outcome through the operator asking for it:
// eq wants equal, ne wants not.
func matchesEquality(op protocol.CompareOp, equal bool) bool {
	if op == protocol.OpNotEqual {
		return !equal
	}
	return equal
}

// compareString applies a string operator, folding case unless the attribute is
// caseExact, which is what makes "userName eq" case insensitive and "externalId
// eq" not -- the same split foldedOperands makes in SQL.
func compareString(op protocol.CompareOp, got, want string, caseExact bool) bool {
	if !caseExact {
		got, want = strings.ToLower(got), strings.ToLower(want)
	}

	switch op {
	case protocol.OpEqual:
		return got == want
	case protocol.OpNotEqual:
		return got != want
	case protocol.OpContains:
		return strings.Contains(got, want)
	case protocol.OpStartsWith:
		return strings.HasPrefix(got, want)
	case protocol.OpEndsWith:
		return strings.HasSuffix(got, want)
	default:
		return false
	}
}
