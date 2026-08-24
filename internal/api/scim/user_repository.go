package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

const scimUsersTable = "scim_users"
const scimUserWhere = " WHERE sso_provider_id = ? AND deleted_at IS NULL"
const scimUserColumns = "id, resource, created_at, updated_at"

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// userSortColumns is what a client may order Users by, mapped to the SQL that
// orders it. A SortBy never reaches a query as text: it selects a value from
// here, or it is refused.
//
// The keys are lowercased because attribute names are case insensitive
// (RFC 7643, Section 2.1). userName folds case because it is not caseExact
// (RFC 7644, Section 3.4.2.3), so paging by it orders on a lowercased code
// point comparison rather than on whatever collation the column happens to run
// under.
var userSortColumns = map[string]string{
	"id":                "id",
	"username":          `lower(user_name) collate "C"`,
	"meta.created":      "created_at",
	"meta.lastmodified": "updated_at",
}

type userRepository struct {
	db      *storage.Connection
	baseURL string
}

type scimUser struct {
	ID            string    `db:"id"`
	SSOProviderID string    `db:"sso_provider_id"`
	UserName      string    `db:"user_name"`
	ExternalID    string    `db:"external_id"`
	Active        bool      `db:"active"`
	Resource      []byte    `db:"resource"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
	DeletedAt     time.Time `db:"deleted_at"`
}

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	var rows []scimUser

	err := r.db.WithContext(ctx).RawQuery("SELECT "+scimUserColumns+" FROM "+scimUsersTable+scimUserWhere+" AND id = ?", r.tenant(ctx), id).All(&rows)
	if err != nil {
		return nil, fmt.Errorf("scim: reading user: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.user(rows[0])
}

func (r *userRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	orderBy, err := userOrderBy(query)
	if err != nil {
		return nil, 0, err
	}

	where, args, err := r.where(ctx, query)
	if err != nil {
		return nil, 0, err
	}

	db := r.db.WithContext(ctx)

	var total int
	if err := db.RawQuery(
		"SELECT COUNT(*) FROM "+scimUsersTable+where,
		args...,
	).First(&total); err != nil {
		return nil, 0, fmt.Errorf("scim: counting users: %w", err)
	}

	// A count of none is answered with the total alone, per Table 6 of RFC 7644,
	// Section 3.4.2.4. A limit of zero is not a query worth issuing.
	if query.Count <= 0 {
		return nil, total, nil
	}

	page := append(slices.Clone(args), query.Count, query.Offset())
	var rows []scimUser
	if err := db.RawQuery(
		"SELECT "+scimUserColumns+" FROM "+scimUsersTable+where+
			" ORDER BY "+orderBy+" LIMIT ? OFFSET ?",
		page...,
	).All(&rows); err != nil {
		return nil, 0, fmt.Errorf("scim: listing users: %w", err)
	}

	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user, err := r.user(row)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, nil
}

func (r *userRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	document, err := userDocument(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery(
		"INSERT INTO "+scimUsersTable+" (sso_provider_id, resource) VALUES (?, ?)"+
			" RETURNING "+scimUserColumns,
		r.tenant(ctx), document,
	).All(&rows); err != nil {
		return nil, r.writeError("creating", err)
	}
	return r.user(rows[0])
}

func (r *userRepository) Replace(ctx context.Context, id string, user *core.User) (*core.User, error) {
	document, err := userDocument(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery(
		"UPDATE "+scimUsersTable+" SET resource = ?, updated_at = now()"+scimUserWhere+
			" AND id = ? RETURNING "+scimUserColumns,
		document, r.tenant(ctx), id,
	).All(&rows); err != nil {
		return nil, r.writeError("replacing", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.user(rows[0])
}

func (r *userRepository) Patch(ctx context.Context, id string, patch *protocol.PatchOp) (*core.User, error) {
	current, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	patched, err := applyUserPatch(current, patch)
	if err != nil {
		return nil, err
	}
	return r.Replace(ctx, id, patched)
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	var ids []string
	if err := r.db.WithContext(ctx).RawQuery("UPDATE "+scimUsersTable+" SET deleted_at = now()"+scimUserWhere+" AND id = ? RETURNING id", r.tenant(ctx), id).All(&ids); err != nil {
		return fmt.Errorf("scim: deleting user: %w", err)
	}
	if len(ids) == 0 {
		return ErrNotFound
	}
	return nil
}

func userDocument(user *core.User) ([]byte, error) {
	stored := *user
	stored.ID = ""
	stored.Meta = core.Meta{}

	document, err := json.Marshal(&stored)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding user: %w", err)
	}
	return document, nil
}

// writeError maps a unique violation on user_name to the 409 of RFC 7644,
// Section 3.3; anything else is this server's problem to log, not the client's
// to read.
func (r *userRepository) writeError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return protocol.ErrUniqueness("a User with this userName already exists")
	}
	return fmt.Errorf("scim: %s user: %w", action, err)
}

// where is the predicate and parameters a List runs under: the tenant scope
// scimUserWhere always carries, and the compiled filter when the query names
// one. The COUNT and the windowed SELECT run under the same where, so they
// count and return the same rows.
func (r *userRepository) where(ctx context.Context, query *protocol.SearchRequest) (string, []any, error) {
	where := scimUserWhere
	args := []any{r.tenant(ctx)}

	filter, err := parseFilterQuery(query)
	if err != nil {
		return "", nil, err
	}
	if filter != nil {
		fragment, fargs, err := compileUserFilter(filter)
		if err != nil {
			return "", nil, err
		}
		where += " AND (" + fragment + ")"
		args = append(args, fargs...)
	}

	return where, args, nil
}

func (r *userRepository) user(row scimUser) (*core.User, error) {
	user := new(core.User)
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, fmt.Errorf("scim: decoding stored user %s: %w", row.ID, err)
	}

	user.ID = row.ID
	user.Meta = core.Meta{
		ResourceType: core.KindUser.Name,
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     core.Join(core.KindUser.Location(r.baseURL), row.ID),
	}

	// A stored User is a User whether or not the document says so, and
	// Section 3.1 does not make "schemas" optional in a response.
	if len(user.Schemas) == 0 {
		user.Schemas = []core.SchemaURI{core.SchemaUser}
	}
	return user, nil
}

func (r *userRepository) tenant(ctx context.Context) string {
	tenant, _ := tenantFrom(ctx)
	return tenant
}

// userOrderBy is the total order the query asks for. Every sort breaks its ties
// on id, because StartIndex and Count are a window and a window over a partial
// order silently skips and repeats rows between pages. Descending reverses the
// tiebreaker too, which keeps the order total rather than only reversing the
// groups.
//
// None of the sortable columns is nullable, so the null ordering of
// Section 3.4.2.3 does not arise here.
func userOrderBy(query *protocol.SearchRequest) (string, error) {
	column := "id"
	if query.SortBy != "" {
		sortable, ok := userSortColumns[strings.ToLower(query.SortBy)]
		if !ok {
			return "", protocol.ErrInvalidValue(strconv.Quote(query.SortBy) +
				" is not an attribute this resource can be sorted by")
		}
		column = sortable
	}

	direction := " ASC"
	if query.Descending() {
		direction = " DESC"
	}

	if column == "id" {
		return column + direction, nil
	}
	return column + direction + ", id" + direction, nil
}

func applyUserPatch(current *core.User, patch *protocol.PatchOp) (*core.User, error) {
	doc, err := userToDoc(current)
	if err != nil {
		return nil, err
	}

	for _, op := range patch.Operations {
		if err := applyPatchOperation(doc, op); err != nil {
			return nil, err
		}
	}

	patched, err := docToUser(doc)
	if err != nil {
		return nil, err
	}
	if patched.UserName == "" {
		return nil, protocol.ErrInvalidValue(`"userName" is required`)
	}
	patched.ID = current.ID
	patched.Meta = current.Meta
	return patched, nil
}

func applyPatchOperation(doc map[string]json.RawMessage, op protocol.PatchOperation) error {
	path, hasPath, err := op.Target()
	if err != nil {
		return err
	}

	switch op.Kind() {
	case protocol.PatchRemove:
		removeDocKey(doc, path.Name, path.Sub)
		return nil

	case protocol.PatchAdd, protocol.PatchReplace:
		if !hasPath {
			return mergeAttributes(doc, op.Value)
		}
		return setDocKey(doc, path.Name, path.Sub, op.Value)

	default:
		return protocol.ErrInvalidValue("unsupported patch operation")
	}
}

func mergeAttributes(doc map[string]json.RawMessage, value json.RawMessage) error {
	var attrs map[string]json.RawMessage
	if err := json.Unmarshal(value, &attrs); err != nil {
		return protocol.ErrInvalidValue("a patch with no path expects a set of attributes to replace")
	}

	for name, raw := range attrs {
		if err := setDocKey(doc, name, "", raw); err != nil {
			return err
		}
	}
	return nil
}

func setDocKey(doc map[string]json.RawMessage, name, sub string, value json.RawMessage) error {
	if sub == "" {
		deleteFold(doc, name)
		doc[name] = value
		return nil
	}

	child, err := childObject(doc, name)
	if err != nil {
		return err
	}
	deleteFold(child, sub)
	child[sub] = value

	encoded, err := json.Marshal(child)
	if err != nil {
		return fmt.Errorf("scim: encoding patched %s: %w", name, err)
	}
	deleteFold(doc, name)
	doc[name] = encoded
	return nil
}

func removeDocKey(doc map[string]json.RawMessage, name, sub string) {
	if sub == "" {
		deleteFold(doc, name)
		return
	}

	child, err := childObject(doc, name)
	if err != nil {
		return
	}
	deleteFold(child, sub)

	if encoded, err := json.Marshal(child); err == nil {
		deleteFold(doc, name)
		doc[name] = encoded
	}
}

func childObject(doc map[string]json.RawMessage, name string) (map[string]json.RawMessage, error) {
	raw, ok := lookupFold(doc, name)
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return map[string]json.RawMessage{}, nil
	}

	var child map[string]json.RawMessage
	if err := json.Unmarshal(raw, &child); err != nil {
		return nil, protocol.ErrInvalidValue(strconv.Quote(name) + " is not a complex attribute")
	}
	return child, nil
}

func lookupFold(doc map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range doc {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func deleteFold(doc map[string]json.RawMessage, name string) {
	for key := range doc {
		if strings.EqualFold(key, name) {
			delete(doc, key)
		}
	}
}

func userToDoc(user *core.User) (map[string]json.RawMessage, error) {
	encoded, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding user to patch: %w", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, fmt.Errorf("scim: reading user to patch: %w", err)
	}
	return doc, nil
}

func docToUser(doc map[string]json.RawMessage) (*core.User, error) {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding patched user: %w", err)
	}

	user := new(core.User)
	if err := json.Unmarshal(encoded, user); err != nil {
		return nil, protocol.ErrInvalidValue("the patched resource is not a valid User")
	}
	return user, nil
}

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
		arg, err := coerceValue(attr, f.Value)
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

// filterKind is how an attribute's values compare, which decides the SQL a
// comparison becomes.
type filterKind int

const (
	filterString filterKind = iota
	filterBool
	filterTime
	filterUUID
)

// filterAttr is an attribute a User can be filtered on: the column that carries
// it in SQL and how its values compare. A filter resolves through this one
// registry, so a filter this server accepts names a column it can push down.
type filterAttr struct {
	column    string
	kind      filterKind
	caseExact bool
}

// userFilterAttrs is the set of attributes promoted to a column, and so the set
// this server can filter Users on. An attribute absent here is one the store
// keeps only inside the resource document, which a pushed-down WHERE cannot
// reach; naming it in a filter is ErrInvalidFilter.
var userFilterAttrs = map[string]filterAttr{
	"username":          {column: "user_name", kind: filterString, caseExact: false},
	"externalid":        {column: "external_id", kind: filterString, caseExact: true},
	"id":                {column: "id", kind: filterUUID, caseExact: true},
	"active":            {column: "active", kind: filterBool},
	"meta.created":      {column: "created_at", kind: filterTime},
	"meta.lastmodified": {column: "updated_at", kind: filterTime},
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

// coerceValue holds a comparison's value to the type attr compares as. Coercion
// runs through this one switch, so the registry alone decides how a filterKind
// reads its compValue -- a mistyped compValue is ErrInvalidFilter rather than a
// query the database rejects.
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

// uuidValue holds an id filter's value to a UUID, returning it canonicalised. A
// value that is not a UUID is ErrInvalidFilter -- the 400 the database would
// otherwise raise as a 500 when it casts the value to the uuid column.
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
