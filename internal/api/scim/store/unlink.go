package store

import (
	"encoding/json"
	"slices"
	"uuid"

	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const selectBody = `
SELECT resource_type, resource
FROM scim_resources
WHERE id = ?`

const updateBody = `
UPDATE scim_resources
SET resource = ?::jsonb
WHERE id = ?`

type body struct {
	Kind     string          `db:"resource_type"`
	Resource json.RawMessage `db:"resource"`
}

// RFC 7643 Section 2.3.7: a soft link to a deleted resource leaves the source.
func (sc scope) unlink(tx *storage.Connection, target uuid.UUID, edges []edge) error {
	for _, e := range edges {
		if e.Target != target {
			continue
		}
		if err := sc.drop(tx, e); err != nil {
			return err
		}
	}
	return nil
}

func (sc scope) drop(tx *storage.Connection, e edge) error {
	var b body
	if err := tx.RawQuery(selectBody, e.Source).First(&b); err != nil {
		return errors.Wrap(err, "error finding SCIM source")
	}
	schemas := sc.db.owners[b.Kind]
	if !slices.ContainsFunc(store.ReferencesOf(schemas), func(ref store.Reference) bool { return ref.Soft() && ref.Name == e.Attribute }) {
		return nil
	}
	object := core.Object{}
	if err := json.Unmarshal(b.Resource, &object); err != nil {
		return err
	}
	store.Unlink(schemas, object, e.Attribute)
	raw, err := json.Marshal(object)
	if err != nil {
		return err
	}
	return errors.Wrap(tx.RawQuery(updateBody, string(raw), e.Source).Exec(), "error unlinking SCIM source")
}
