package models

import (
	"bytes"
	"database/sql"
	"encoding/json"
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

type SCIMAttribute int

const (
	SCIMAttributeName SCIMAttribute = iota + 1
	SCIMAttributeExternalID
	SCIMAttributeActive
)

type SCIMFilter struct {
	Attribute SCIMAttribute
	Value     any
	Match     map[string]any
	And       []SCIMFilter
	Or        []SCIMFilter
}

func (f SCIMFilter) matchesResource() bool {
	terms := append(slices.Clone(f.And), f.Or...)
	return f.Match != nil || slices.ContainsFunc(terms, SCIMFilter.matchesResource)
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

func (t scimTable) where(providerID uuid.UUID, filter SCIMFilter) (string, []any, error) {
	clauses := []string{"sso_provider_id = ?"}
	args := []any{providerID}
	if t.liveClause != "" {
		clauses = append(clauses, t.liveClause)
	}
	clause, values, err := t.filter(filter)
	if clause != "" {
		clauses = append(clauses, clause)
		args = append(args, values...)
	}
	return strings.Join(clauses, " AND "), args, err
}

func (t scimTable) filter(filter SCIMFilter) (string, []any, error) {
	switch {
	case filter.Attribute == SCIMAttributeName:
		return t.nameColumn + ` COLLATE "C" = lower(?)`, []any{filter.Value}, nil
	case filter.Attribute == SCIMAttributeExternalID:
		return `external_id COLLATE "C" = ?`, []any{filter.Value}, nil
	case filter.Attribute == SCIMAttributeActive && filter.Value == true:
		return "active", nil, nil
	case filter.Attribute == SCIMAttributeActive:
		return "NOT active", nil, nil
	case filter.Match != nil:
		return scimMatch(filter)
	case len(filter.Or) > 0:
		return t.join(filter.Or, " OR ")
	}
	return t.join(filter.And, " AND ")
}

func (t scimTable) join(terms []SCIMFilter, operator string) (string, []any, error) {
	if len(terms) == 0 {
		return "", nil, nil
	}
	clauses, args := make([]string, len(terms)), []any{}
	for i, term := range terms {
		clause, values, err := t.filter(term)
		if err != nil {
			return "", nil, err
		}
		clauses[i] = clause
		args = append(args, values...)
	}
	return "(" + strings.Join(clauses, operator) + ")", args, nil
}

func scimMatch(filter SCIMFilter) (string, []any, error) {
	match, err := json.Marshal(filter.Match)
	if err != nil {
		return "", nil, err
	}
	return "lower(resource::text)::jsonb @> lower(?)::jsonb", []any{string(match)}, nil
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
	where, args, err := table.where(providerID, query.Filter)
	if err != nil {
		return nil, 0, err
	}
	source := fmt.Sprintf("%q WHERE %s", table.tableName, where)
	if query.Filter.matchesResource() {
		source = fmt.Sprintf("(SELECT * FROM %s OFFSET 0) AS %q", source, table.tableName)
	}
	rows := []T{}
	if query.Limit > 0 {
		if err := tx.RawQuery(
			fmt.Sprintf("SELECT %s FROM %s ORDER BY %s OFFSET ? LIMIT ?", table.columns, source, table.orderBy(query.Order)),
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
