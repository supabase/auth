package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

const getUser = `SELECT id, resource, active, created_at, updated_at FROM scim_users
	WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ?`

const createUser = `INSERT INTO scim_users (sso_provider_id, resource)
	VALUES (?, ?) RETURNING id, resource, active, created_at, updated_at`

// Replace overwrites the stored document, but active is the leaver path's to
// change (AUTH-1360): when the body omits it, the stored value is carried over.
const replaceUser = `UPDATE scim_users
	SET resource = jsonb_set(?::jsonb, '{active}', coalesce(?::jsonb -> 'active', to_jsonb(active))),
		updated_at = now()
	WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ?
	RETURNING id, resource, active, created_at, updated_at`

const deleteUser = `UPDATE scim_users SET deleted_at = now()
	WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ? RETURNING id`

const countUsers = `SELECT COUNT(*) FROM scim_users
	WHERE sso_provider_id = ? AND deleted_at IS NULL`

const listUsers = `SELECT id, resource, active, created_at, updated_at FROM scim_users
	WHERE sso_provider_id = ? AND deleted_at IS NULL
	ORDER BY %s LIMIT ? OFFSET ?`

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

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	var rows []scimUser

	if err := r.db.WithContext(ctx).RawQuery(getUser, r.tenant(ctx), id).All(&rows); err != nil {
		return nil, fmt.Errorf("scim: reading user: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.mapFrom(&rows[0])
}

func (r *userRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	if query.Filter != "" {
		return nil, 0, protocol.ErrInvalidFilter("filtering is not supported")
	}

	orderBy, err := r.orderBy(query)
	if err != nil {
		return nil, 0, err
	}

	db := r.db.WithContext(ctx)
	tenant := r.tenant(ctx)

	var total int
	if err := db.RawQuery(countUsers, tenant).First(&total); err != nil {
		return nil, 0, fmt.Errorf("scim: counting users: %w", err)
	}

	if query.Count <= 0 {
		return nil, total, nil
	}

	var rows []scimUser
	if err := db.RawQuery(fmt.Sprintf(listUsers, orderBy), tenant, query.Count, query.Offset()).All(&rows); err != nil {
		return nil, 0, fmt.Errorf("scim: listing users: %w", err)
	}

	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user, err := r.mapFrom(&row)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, nil
}

func (r *userRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	resource, err := r.toResource(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery(createUser, r.tenant(ctx), resource).All(&rows); err != nil {
		return nil, r.buildError("creating", err)
	}
	return r.mapFrom(&rows[0])
}

// toResource is the document that gets stored. id and meta are the store's to
// assign, so a client cannot dictate them.
func (r *userRepository) toResource(user *core.User) ([]byte, error) {
	stored := *user
	stored.ID = ""
	stored.Meta = core.Meta{}

	resource, err := json.Marshal(&stored)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding user: %w", err)
	}
	return resource, nil
}

func (r *userRepository) buildError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return protocol.ErrUniqueness("a User with this userName already exists")
	}
	return fmt.Errorf("scim: %s user: %w", action, err)
}

func (r *userRepository) Replace(ctx context.Context, id string, user *core.User) (*core.User, error) {
	resource, err := r.toResource(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery(replaceUser, string(resource), string(resource), r.tenant(ctx), id).All(&rows); err != nil {
		return nil, r.buildError("replacing", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.mapFrom(&rows[0])
}

// Delete is a soft delete: the tombstone keeps the row so a userName is not
// silently reusable and the record survives the auth user being removed.
func (r *userRepository) Delete(ctx context.Context, id string) error {
	var ids []string
	if err := r.db.WithContext(ctx).RawQuery(deleteUser, r.tenant(ctx), id).All(&ids); err != nil {
		return fmt.Errorf("scim: deleting user: %w", err)
	}
	if len(ids) == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *userRepository) mapFrom(row *scimUser) (*core.User, error) {
	user := new(core.User)
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, fmt.Errorf("scim: decoding stored user %s: %w", row.ID, err)
	}

	user.ID = row.ID
	user.Active = &row.Active
	user.Meta = core.NewMeta(r.baseURL, core.KindUser).For(row)

	if len(user.Schemas) == 0 {
		user.Schemas = []core.SchemaURI{core.SchemaUser}
	}
	return user, nil
}

// orderBy maps a SCIM sort attribute onto a column, per RFC 7644, Section 3.4.2.3.
// Every ordering breaks ties on id so a page walk sees a total order.
func (r *userRepository) orderBy(query *protocol.SearchRequest) (string, error) {
	column := "id"
	if query.SortBy != "" {
		sortable, ok := userSortColumns[strings.ToLower(query.SortBy)]
		if !ok {
			return "", protocol.ErrInvalidValue(strconv.Quote(query.SortBy) + " is not an attribute this resource can be sorted by")
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

func (r *userRepository) tenant(ctx context.Context) string {
	tenant, _ := tenantFrom(ctx)
	return tenant
}
