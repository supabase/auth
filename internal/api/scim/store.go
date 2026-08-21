package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

// scimUsersTable is unqualified so that it resolves through the connection's
// search_path, as every table named in internal/models does. Which schema that
// is comes from DB_NAMESPACE.
const scimUsersTable = "scim_users"

// scimUserWhere is the predicate every query in this repository carries. It is
// written once so that no query can be assembled without it: the tenant scopes
// the row, and a soft-deleted row is gone.
const scimUserWhere = " WHERE sso_provider_id = ? AND deleted_at IS NULL"

const scimUserColumns = "id, resource, created_at, updated_at"

// userSortColumns is what a client may order Users by, mapped to the SQL that
// orders it. A SortBy never reaches a query as text: it selects a value from
// here, or it is refused.
//
// The keys are lowercased because attribute names are case insensitive
// (RFC 7643, Section 2.1). userName folds case because it is not caseExact
// (RFC 7644, Section 3.4.2.3), which is also what MemoryStore does -- the two
// have to agree or paging one differs from paging the other.
var userSortColumns = map[string]string{
	"id":                "id",
	"username":          `lower(user_name) collate "C"`,
	"meta.created":      "created_at",
	"meta.lastmodified": "updated_at",
}

type userStore struct {
	db       *storage.Connection
	usersURL string
}

// NewUserStore serves Users out of Postgres. externalURL is where this
// deployment answers, which is what makes a stored row addressable as
// meta.location.
func NewUserStore(db *storage.Connection, externalURL string) Store[*core.User] {
	return &userStore{
		db:       db,
		usersURL: core.KindUser.Location(core.Join(externalURL, BasePath)),
	}
}

func (s *userStore) For(tenant string) Repository[*core.User] {
	return &userRepository{store: s, tenant: tenant}
}

// userRepository is one tenant's Users. The tenant is a field rather than a
// parameter so that every query it builds carries scimUserWhere.
type userRepository struct {
	store  *userStore
	tenant string
}

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	var rows []scimUserRow

	err := r.store.db.WithContext(ctx).RawQuery(
		"SELECT "+scimUserColumns+" FROM "+scimUsersTable+scimUserWhere+" AND id = ?",
		r.tenant, id,
	).All(&rows)
	if err != nil {
		return nil, fmt.Errorf("scim: reading user: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.store.user(rows[0])
}

func (r *userRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	orderBy, err := userOrderBy(query)
	if err != nil {
		return nil, 0, err
	}

	where, args, err := r.where(query)
	if err != nil {
		return nil, 0, err
	}

	db := r.store.db.WithContext(ctx)

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
	var rows []scimUserRow
	if err := db.RawQuery(
		"SELECT "+scimUserColumns+" FROM "+scimUsersTable+where+
			" ORDER BY "+orderBy+" LIMIT ? OFFSET ?",
		page...,
	).All(&rows); err != nil {
		return nil, 0, fmt.Errorf("scim: listing users: %w", err)
	}

	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user, err := r.store.user(row)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, nil
}

// where is the predicate and parameters a List runs under: the tenant scope
// scimUserWhere always carries, and the compiled filter when the query names
// one. The COUNT and the windowed SELECT run under the same where, so they
// count and return the same rows.
func (r *userRepository) where(query *protocol.SearchRequest) (string, []any, error) {
	where := scimUserWhere
	args := []any{r.tenant}

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

type scimUserRow struct {
	ID        string    `db:"id"`
	Resource  []byte    `db:"resource"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// user rebuilds a resource from its row. The document holds what a client
// supplied; id and meta are this server's to assert, per RFC 7643,
// Section 3.1, so they come from the columns rather than the document.
func (s *userStore) user(row scimUserRow) (*core.User, error) {
	user := new(core.User)
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, fmt.Errorf("scim: decoding stored user %s: %w", row.ID, err)
	}

	user.ID = row.ID
	user.Meta = core.Meta{
		ResourceType: core.KindUser.Name,
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     core.Join(s.usersURL, row.ID),
	}

	// A stored User is a User whether or not the document says so, and
	// Section 3.1 does not make "schemas" optional in a response.
	if len(user.Schemas) == 0 {
		user.Schemas = []core.SchemaURI{core.SchemaUser}
	}
	return user, nil
}
