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

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

const scimUsersTable = "scim_users"
const scimUserWhere = " WHERE sso_provider_id = ? AND deleted_at IS NULL"
const scimUserColumns = "id, resource, created_at, updated_at"

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
