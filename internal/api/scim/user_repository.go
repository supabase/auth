package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/storage"
)

var ErrNotFound = errors.New("scim: resource not found")

var userSortColumns = map[string]string{
	"id":                "id",
	"username":          `lower(user_name collate "C")`,
	"meta.created":      "created_at",
	"meta.lastmodified": "updated_at",
}

const countUsers = `SELECT COUNT(*) FROM scim_users WHERE sso_provider_id = ? AND deleted_at IS NULL`

const listUsers = `SELECT id, resource, active, created_at, updated_at FROM scim_users WHERE sso_provider_id = ? AND deleted_at IS NULL ORDER BY %s LIMIT ? OFFSET ?`

type scimUser struct {
	ID        string    `db:"id"`
	Resource  []byte    `db:"resource"`
	Active    bool      `db:"active"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (scimUser) TableName() string {
	return "scim_users"
}

type userRepository struct {
	db      *storage.Connection
	baseURL string
}

func NewUserRepository(db *storage.Connection, baseURL string) Repository[*core.User] {
	return &userRepository{
		db:      db,
		baseURL: baseURL,
	}
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

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	var rows []scimUser

	err := r.db.WithContext(ctx).RawQuery("SELECT id, resource, active, created_at, updated_at FROM scim_users WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ?", r.tenant(ctx), id).All(&rows)
	if err != nil {
		return nil, fmt.Errorf("scim: reading user: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.mapFrom(&rows[0])
}

func (r *userRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	resource, err := r.toResource(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery("INSERT INTO scim_users (id, sso_provider_id, resource) VALUES (?, ?, ?) RETURNING id, resource, active, created_at, updated_at", uuid.Must(uuid.NewV4()), r.tenant(ctx), resource).All(&rows); err != nil {
		return nil, r.buildError("creating", err)
	}
	return r.mapFrom(&rows[0])
}

func (r *userRepository) Replace(ctx context.Context, id string, user *core.User) (*core.User, error) {
	resource, err := r.toResource(user)
	if err != nil {
		return nil, err
	}

	var rows []scimUser
	if err := r.db.WithContext(ctx).RawQuery("UPDATE scim_users SET resource = jsonb_set(?::jsonb, '{active}', coalesce(?::jsonb -> 'active', to_jsonb(active))), updated_at = now() WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ? RETURNING id, resource, active, created_at, updated_at", string(resource), string(resource), r.tenant(ctx), id).All(&rows); err != nil {
		return nil, r.buildError("replacing", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.mapFrom(&rows[0])
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	var ids []string
	if err := r.db.WithContext(ctx).RawQuery("UPDATE scim_users SET deleted_at = now() WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ? RETURNING id", r.tenant(ctx), id).All(&ids); err != nil {
		return fmt.Errorf("scim: deleting user: %w", err)
	}
	if len(ids) == 0 {
		return ErrNotFound
	}
	return nil
}

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

func (r *userRepository) mapFrom(row *scimUser) (*core.User, error) {
	user := new(core.User)
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, fmt.Errorf("scim: decoding stored user %s: %w", row.ID, err)
	}

	user.ID = row.ID
	user.Active = &row.Active
	user.Meta = core.Meta{
		ResourceType: "User",
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     Join(Join(r.baseURL, "/Users"), row.ID),
	}

	if len(user.Schemas) == 0 {
		user.Schemas = []core.SchemaURI{core.SchemaUser}
	}
	return user, nil
}

func (r *userRepository) tenant(ctx context.Context) string {
	return tenantKey.Value(ctx).ID.String()
}

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
