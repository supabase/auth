package store

import (
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const softDeleteResource = `
UPDATE scim_resources
SET deleted_at = now()
WHERE id = ?
  AND ` + scopeWhere + `
  AND updated_at = COALESCE(?, updated_at)`

func (sc scope) remove(tx *storage.Connection, id uuid.UUID, version string) error {
	ends, err := sc.edges(tx, id)
	if err != nil {
		return err
	}
	count, err := tx.RawQuery(
		softDeleteResource,
		id, sc.providerID, sc.Type, versionTime(version),
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return store.ErrNoMatch
	}
	if err := sc.unlink(tx, id, ends); err != nil {
		return err
	}
	return sc.bump(tx, id, others(id, ends))
}
