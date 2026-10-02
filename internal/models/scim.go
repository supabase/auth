package models

import (
	"bytes"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgtype"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const scimVersionClause = "(?::timestamptz IS NULL OR updated_at = ?)"

type SCIMFilter struct {
	Name       *string
	ExternalID *string
}

type SCIMSortKey int

const (
	SCIMSortByCreatedAt SCIMSortKey = iota
	SCIMSortByID
	SCIMSortByName
	SCIMSortByUpdatedAt
)

type SCIMOrder struct {
	By         SCIMSortKey
	Descending bool
}

type SCIMQuery struct {
	Filter SCIMFilter
	Order  SCIMOrder
	Offset int
	Limit  int
}

type SCIMTarget struct {
	ProviderID uuid.UUID
	ID         uuid.UUID
	UpdatedAt  *time.Time
}

type scimTable struct {
	tableName  string
	label      string
	columns    string
	nameColumn string
	liveClause string
	conflict   error
}

func (t scimTable) where(providerID uuid.UUID, filter SCIMFilter) (string, []any) {
	clauses := []string{"sso_provider_id = ?"}
	args := []any{providerID}
	if t.liveClause != "" {
		clauses = append(clauses, t.liveClause)
	}
	if filter.Name != nil {
		clauses = append(clauses, t.nameColumn+` COLLATE "C" = lower(?)`)
		args = append(args, *filter.Name)
	}
	if filter.ExternalID != nil {
		clauses = append(clauses, "external_id = ?")
		args = append(args, *filter.ExternalID)
	}
	return strings.Join(clauses, " AND "), args
}

func (t scimTable) targetClause() string {
	if t.liveClause == "" {
		return "id = ? AND sso_provider_id = ?"
	}
	return "id = ? AND sso_provider_id = ? AND " + t.liveClause
}

func (t scimTable) exists(tx *storage.Connection, target SCIMTarget) (bool, error) {
	var result struct {
		Exists bool `db:"exists"`
	}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %q WHERE %s) AS exists", t.tableName, t.targetClause()),
		target.ID, target.ProviderID,
	).First(&result); err != nil {
		return false, errors.Wrapf(err, "error finding %s", t.label)
	}
	return result.Exists, nil
}

func (t scimTable) writeError(tx *storage.Connection, target SCIMTarget, err error, verb string) error {
	if !errors.Is(err, sql.ErrNoRows) || target.UpdatedAt == nil {
		return t.wrapError(err, verb)
	}
	exists, findErr := t.exists(tx, target)
	if findErr != nil {
		return findErr
	}
	if !exists {
		return SCIMNotFoundError{}
	}
	return SCIMStaleError{}
}

func (t scimTable) orderBy(order SCIMOrder) string {
	direction := "ASC"
	if order.Descending {
		direction = "DESC"
	}
	switch order.By {
	case SCIMSortByID:
		return "id " + direction
	case SCIMSortByName:
		return t.nameColumn + ` COLLATE "C" ` + direction + ", id " + direction
	case SCIMSortByUpdatedAt:
		return "updated_at " + direction + ", id " + direction
	}
	return "created_at " + direction + ", id " + direction
}

func (t scimTable) wrapError(err error, verb string) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return SCIMNotFoundError{}
	case isUniqueViolation(err):
		return t.conflict
	}
	return errors.Wrapf(err, "error %s %s", verb, t.label)
}

func findSCIMPage[T any](tx *storage.Connection, table scimTable, providerID uuid.UUID, query SCIMQuery) ([]T, int, error) {
	where, args := table.where(providerID, query.Filter)
	rows := []T{}
	if query.Limit > 0 {
		if err := tx.RawQuery(
			fmt.Sprintf("SELECT %s FROM %q WHERE %s ORDER BY %s OFFSET ? LIMIT ?", table.columns, table.tableName, where, table.orderBy(query.Order)),
			append(slices.Clone(args), query.Offset, query.Limit)...,
		).All(&rows); err != nil {
			return nil, 0, errors.Wrapf(err, "error finding %ss", table.label)
		}
		lastPage := len(rows) < query.Limit && (query.Offset == 0 || len(rows) > 0)
		if lastPage {
			return rows, query.Offset + len(rows), nil
		}
	}
	total, err := tx.Q().Where(where, args...).Count(new(T))
	if err != nil {
		return nil, 0, errors.Wrapf(err, "error counting %ss", table.label)
	}
	return rows, total, nil
}

func createSCIMRow[T any](tx *storage.Connection, table scimTable, providerID uuid.UUID, resource []byte) (*T, error) {
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource) VALUES (?, ?, ?::jsonb) RETURNING %s", table.tableName, table.columns),
		uuid.Must(uuid.NewV4()), providerID, string(resource),
	).First(row); err != nil {
		return nil, table.wrapError(err, "creating")
	}
	return row, nil
}

func findSCIMRow[T any](tx *storage.Connection, table scimTable, target SCIMTarget) (*T, error) {
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT %s FROM %q WHERE %s", table.columns, table.tableName, table.targetClause()),
		target.ID, target.ProviderID,
	).First(row); err != nil {
		return nil, table.wrapError(err, "finding")
	}
	return row, nil
}

func findUnchangedSCIMRow[T any](tx *storage.Connection, table scimTable, target SCIMTarget, resource []byte) (*T, error) {
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT %s FROM %q WHERE %s AND resource = ?::jsonb AND "+scimVersionClause+" FOR UPDATE", table.columns, table.tableName, table.targetClause()),
		target.ID, target.ProviderID, string(resource), target.UpdatedAt, target.UpdatedAt,
	).First(row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, table.wrapError(err, "finding")
	}
	return row, nil
}

func replaceSCIMRowIfChanged[T any](tx *storage.Connection, table scimTable, target SCIMTarget, resource []byte) (*T, bool, error) {
	unchanged, err := findUnchangedSCIMRow[T](tx, table, target, resource)
	if err != nil || unchanged != nil {
		return unchanged, false, err
	}
	row, err := replaceSCIMRow[T](tx, table, target, resource)
	return row, err == nil, err
}

func replaceSCIMRow[T any](tx *storage.Connection, table scimTable, target SCIMTarget, resource []byte) (*T, error) {
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = clock_timestamp() WHERE %s AND "+scimVersionClause+" RETURNING %s", table.tableName, table.targetClause(), table.columns),
		string(resource), target.ID, target.ProviderID, target.UpdatedAt, target.UpdatedAt,
	).First(row); err != nil {
		return nil, table.writeError(tx, target, err, "replacing")
	}
	return row, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}

func isCheckViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.CheckViolation && pgErr.ConstraintName == constraint
}

func differenceUUIDs(from, subtract []uuid.UUID) []uuid.UUID {
	exclude := make(map[uuid.UUID]struct{}, len(subtract))
	for _, id := range subtract {
		exclude[id] = struct{}{}
	}
	result := []uuid.UUID{}
	for _, id := range from {
		if _, ok := exclude[id]; !ok {
			result = append(result, id)
		}
	}
	return result
}

func sortedUniqueUUIDs(ids []uuid.UUID) []uuid.UUID {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(sorted)
}

func uuidArray(ids []uuid.UUID) *pgtype.UUIDArray {
	array := &pgtype.UUIDArray{Elements: make([]pgtype.UUID, len(ids)), Status: pgtype.Present}
	for i, id := range ids {
		array.Elements[i] = pgtype.UUID{Bytes: id, Status: pgtype.Present}
	}
	length := len(ids)
	if length == 0 || length > math.MaxInt32 {
		return array
	}
	array.Dimensions = []pgtype.ArrayDimension{{Length: int32(length), LowerBound: 1}}
	return array
}
