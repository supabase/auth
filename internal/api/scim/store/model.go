package store

import (
	"encoding/json"
	"time"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase-community/scim-go/pkg/store"
)

type model struct {
	ID        uuid.UUID       `db:"id"`
	Resource  json.RawMessage `db:"resource"`
	CreatedAt time.Time       `db:"created_at"`
	UpdatedAt time.Time       `db:"updated_at"`
}

func (model) TableName() string {
	return "scim_resources"
}

func (m model) record() store.Record {
	return store.Record{
		ID:      m.ID.String(),
		Body:    m.Resource,
		Created: m.CreatedAt,
		Updated: m.UpdatedAt,
		Version: server.WeakETag(m.UpdatedAt),
	}
}

func records(rows []model) []store.Record {
	out := make([]store.Record, len(rows))
	for i, m := range rows {
		out[i] = m.record()
	}
	return out
}
