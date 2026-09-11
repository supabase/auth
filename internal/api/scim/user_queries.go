package scim

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/storage"
)

var filterColumns = map[string]string{
	"id":                "id",
	"username":          "user_name",
	"externalid":        "external_id",
	"active":            "active",
	"meta.created":      "created_at",
	"meta.lastmodified": "updated_at",
}

var userSortColumns = buildSortColumns()

func buildSortColumns() map[string]string {
	sortable := []string{"id", "username", "meta.created", "meta.lastmodified"}
	columns := make(map[string]string, len(sortable))
	for _, key := range sortable {
		columns[key] = filterColumns[key]
	}
	columns["username"] = `lower(` + filterColumns["username"] + ` collate "C")`
	return columns
}

const countUsers = `SELECT COUNT(*) FROM scim_users WHERE sso_provider_id = ? AND deleted_at IS NULL%s`

const listUsers = `SELECT id, resource, active, created_at, updated_at FROM scim_users WHERE sso_provider_id = ? AND deleted_at IS NULL%s ORDER BY %s LIMIT ? OFFSET ?`

func (r *userRepository) filterClause(query *protocol.SearchRequest) (string, []any, error) {
	if query.Filter == "" {
		return "", nil, nil
	}

	fragment, err := protocol.Filter[sqlFragment]([]*core.Schema{r.schema}, query.Filter, &sqlEvaluator{})
	if err != nil {
		return "", nil, err
	}
	return " AND (" + fragment.sql + ")", fragment.args, nil
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

	direction := sortDirection(query)
	if column == "id" {
		return column + direction, nil
	}
	return column + direction + ", id" + direction, nil
}

func sortDirection(query *protocol.SearchRequest) string {
	if query.Descending() {
		return " DESC"
	}
	return " ASC"
}

func (r *userRepository) count(db *storage.Connection, tenant, filterSQL string, args []any) (int, error) {
	countArgs := append([]any{tenant}, args...)
	var total int
	if err := db.RawQuery(fmt.Sprintf(countUsers, filterSQL), countArgs...).First(&total); err != nil {
		return 0, fmt.Errorf("scim: counting users: %w", err)
	}
	return total, nil
}

func (r *userRepository) page(db *storage.Connection, tenant, filterSQL, orderBy string, args []any, query *protocol.SearchRequest) ([]*core.User, error) {
	listArgs := append(append([]any{tenant}, args...), query.Count, query.Offset())
	var rows []scimUser
	if err := db.RawQuery(fmt.Sprintf(listUsers, filterSQL, orderBy), listArgs...).All(&rows); err != nil {
		return nil, fmt.Errorf("scim: listing users: %w", err)
	}

	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user, err := r.mapFrom(&row)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}
