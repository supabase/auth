package store

import (
	"fmt"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

const scopeWhere = "sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL"

const selectResources = `
SELECT id, %s AS resource, created_at, updated_at
FROM %s`

const resourceByID = `scim_resources
WHERE id = ?
  AND ` + scopeWhere

func (sc scope) find(tx *storage.Connection, id uuid.UUID, refs []store.Reference) (store.Record, error) {
	rows, err := sc.fetch(tx, selection(refs), resourceByID, id, sc.providerID, sc.Type)
	if err != nil {
		return store.Record{}, err
	}
	if len(rows) == 0 {
		return store.Record{}, notFound()
	}
	return rows[0].record(), nil
}

func (sc scope) fetch(tx *storage.Connection, selection, from string, args ...any) ([]model, error) {
	rows := []model{}
	err := tx.RawQuery(fmt.Sprintf(selectResources, selection, from), args...).All(&rows)
	return rows, err
}

func selection(refs []store.Reference) string {
	if len(refs) == 0 {
		return "resource"
	}
	pairs := make([]string, len(refs))
	for i, ref := range refs {
		pairs[i] = query.Reference{Reference: ref}.Pair()
	}
	return "resource || jsonb_strip_nulls(jsonb_build_object(" + strings.Join(pairs, ", ") + "))"
}
