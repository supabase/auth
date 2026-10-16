package store

import (
	"strconv"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/storage"
)

const selectCycle = `
WITH RECURSIVE up (id) AS (
  SELECT ?::uuid
  UNION
  SELECT r.source_id
  FROM up u
  JOIN scim_resource_references r ON r.target_id = u.id AND r.attribute = ?
)
SELECT id
FROM up
WHERE id = any(?::uuid[])
LIMIT 1`

func (sc scope) acyclic(tx *storage.Connection, source uuid.UUID, attribute string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	cyclic := []uuid.UUID{}
	err := tx.RawQuery(
		selectCycle,
		source, attribute, targets,
	).All(&cyclic)
	if err != nil {
		return errors.Wrap(err, "error finding SCIM cycles")
	}
	if len(cyclic) > 0 {
		return scimerrors.ErrInvalidValue(strconv.Quote(cyclic[0].String()) + " would make " + attribute + " cyclic")
	}
	return nil
}
