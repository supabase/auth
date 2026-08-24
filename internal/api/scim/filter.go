package scim

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"

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
	filterUUID
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
		column: "id", kind: filterUUID, caseExact: true,
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

	attr, ok := userFilterAttrs[strings.ToLower(nameSub(path))]
	if !ok {
		return filterAttr{}, unfilterable(path)
	}
	return attr, nil
}

// nameSub is the attrPath's attribute name with its sub-attribute joined on,
// without the schema URI -- the text a filter names a column by.
func nameSub(path protocol.AttrPath) string {
	if path.Sub == "" {
		return path.Name
	}
	return path.Name + "." + path.Sub
}

func unfilterable(path protocol.AttrPath) error {
	return protocol.ErrInvalidFilter(strconv.Quote(nameSub(path)) + " is not an attribute this server can filter on")
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

// coerceValue holds a comparison's value to the type attr compares as. Both
// stores coerce through this one switch, so the registry alone decides how a
// filterKind reads its compValue -- a mistyped compValue is ErrInvalidFilter
// rather than a query the database rejects.
func coerceValue(attr filterAttr, v protocol.Value) (any, error) {
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

// rawAs holds a filter's value to the type its attribute compares as, or
// ErrInvalidFilter when the decoded compValue is the wrong JSON type.
func rawAs[T any](v protocol.Value, expected string) (T, error) {
	t, ok := v.Raw.(T)
	if !ok {
		var zero T
		return zero, protocol.ErrInvalidFilter(expected)
	}
	return t, nil
}

func stringValue(v protocol.Value) (string, error) {
	return rawAs[string](v, "a string value was expected")
}

func boolValue(v protocol.Value) (bool, error) {
	return rawAs[bool](v, "a boolean value was expected")
}

func timeValue(v protocol.Value) (time.Time, error) {
	s, err := rawAs[string](v, "a dateTime string was expected")
	if err != nil {
		return time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, protocol.ErrInvalidFilter(strconv.Quote(s) + " is not a valid dateTime")
	}
	return at, nil
}

// uuidValue holds an id filter's value to a UUID, returning it canonicalised so
// that both stores compare the same text. A value that is not a UUID is
// ErrInvalidFilter -- the 400 the database would otherwise raise as a 500 when
// it casts the value to the uuid column.
func uuidValue(v protocol.Value) (string, error) {
	s, err := rawAs[string](v, "a string value was expected")
	if err != nil {
		return "", err
	}
	id, err := uuid.FromString(s)
	if err != nil {
		return "", protocol.ErrInvalidFilter(strconv.Quote(s) + " is not a valid id")
	}
	return id.String(), nil
}
