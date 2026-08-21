package scim

import (
	"strconv"
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

// filterKind is how an attribute's values compare, which decides both the SQL a
// comparison becomes and how it is evaluated in memory.
type filterKind int

const (
	filterString filterKind = iota
	filterBool
	filterTime
)

// filterAttr is an attribute a User can be filtered on: the column that carries
// it in SQL, how to read it from a User in memory, and how its values compare.
// Both stores resolve through this one registry so that a filter this server
// accepts means the same thing whichever store answers it.
type filterAttr struct {
	column    string
	kind      filterKind
	caseExact bool
	valueOf   func(u *core.User) (any, bool)
}

// userFilterAttrs is the set of attributes promoted to a column, and so the set
// this server can filter Users on. An attribute absent here is one the store
// keeps only inside the resource document, which a pushed-down WHERE cannot
// reach; naming it in a filter is ErrInvalidFilter.
var userFilterAttrs = map[string]filterAttr{
	"username": {
		column: "user_name", kind: filterString, caseExact: false,
		valueOf: func(u *core.User) (any, bool) { return u.UserName, u.UserName != "" },
	},
	"externalid": {
		column: "external_id", kind: filterString, caseExact: true,
		valueOf: func(u *core.User) (any, bool) { return u.ExternalID, u.ExternalID != "" },
	},
	"id": {
		column: "id", kind: filterString, caseExact: true,
		valueOf: func(u *core.User) (any, bool) { return u.ID, u.ID != "" },
	},
	"active": {
		column: "active", kind: filterBool,
		valueOf: func(u *core.User) (any, bool) { return activeOrDefault(u), true },
	},
	"meta.created": {
		column: "created_at", kind: filterTime,
		valueOf: func(u *core.User) (any, bool) { return u.Meta.Created, !u.Meta.Created.IsZero() },
	},
	"meta.lastmodified": {
		column: "updated_at", kind: filterTime,
		valueOf: func(u *core.User) (any, bool) { return u.Meta.LastModified, !u.Meta.LastModified.IsZero() },
	},
}

// activeOrDefault mirrors the active column: an absent active is true, which is
// what coalesce((resource->>'active')::boolean, true) yields in the database.
// The two stores must agree on this, or "active eq true" pages differently.
func activeOrDefault(u *core.User) bool {
	return u.Active == nil || *u.Active
}

// parseFilterQuery parses the filter a query carries, or nil when it carries
// none. A malformed filter is ErrInvalidFilter, ready to answer the request.
func parseFilterQuery(query *protocol.SearchRequest) (protocol.Filter, error) {
	if query.Filter == "" {
		return nil, nil
	}
	return protocol.ParseFilter(query.Filter)
}

// resolveUserFilterAttr resolves an attrPath to the attribute it names, or
// ErrInvalidFilter if this server does not serve it as a column. A schema URI is
// honoured only when it is the core User schema: an extension attribute lives in
// the document, not a column, so it is not filterable.
func resolveUserFilterAttr(path protocol.AttrPath) (filterAttr, error) {
	if path.URI != "" && path.URI != string(core.SchemaUser) {
		return filterAttr{}, unfilterable(path)
	}

	key := strings.ToLower(path.Name)
	if path.Sub != "" {
		key += "." + strings.ToLower(path.Sub)
	}

	attr, ok := userFilterAttrs[key]
	if !ok {
		return filterAttr{}, unfilterable(path)
	}
	return attr, nil
}

func unfilterable(path protocol.AttrPath) error {
	name := path.Name
	if path.Sub != "" {
		name += "." + path.Sub
	}
	return protocol.ErrInvalidFilter(strconv.Quote(name) + " is not an attribute this server can filter on")
}

// checkOp reports whether attr may be compared with op. Presence and equality
// apply to every attribute; the substring operators are for strings; the
// ordering operators are parsed but not served, which is the subset this store
// pushes down.
func checkOp(attr filterAttr, op protocol.CompareOp) error {
	switch op {
	case protocol.OpPresent, protocol.OpEqual, protocol.OpNotEqual:
		return nil
	case protocol.OpContains, protocol.OpStartsWith, protocol.OpEndsWith:
		if attr.kind != filterString {
			return protocol.ErrInvalidFilter(string(op) + " is only supported on string attributes")
		}
		return nil
	default:
		return protocol.ErrInvalidFilter(strconv.Quote(string(op)) + " is not a supported filter operator")
	}
}

// The value extractors below hold a filter's value to the type its attribute
// compares as, so that a mistyped compValue is ErrInvalidFilter rather than a
// query the database rejects.

func stringValue(v protocol.Value) (string, error) {
	s, ok := v.Raw.(string)
	if !ok {
		return "", protocol.ErrInvalidFilter("a string value was expected")
	}
	return s, nil
}

func boolValue(v protocol.Value) (bool, error) {
	b, ok := v.Raw.(bool)
	if !ok {
		return false, protocol.ErrInvalidFilter("a boolean value was expected")
	}
	return b, nil
}

func timeValue(v protocol.Value) (time.Time, error) {
	s, ok := v.Raw.(string)
	if !ok {
		return time.Time{}, protocol.ErrInvalidFilter("a dateTime string was expected")
	}
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, protocol.ErrInvalidFilter(strconv.Quote(s) + " is not a valid dateTime")
	}
	return at, nil
}
