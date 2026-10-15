package store

import (
	"encoding/json"
	"time"
	"uuid"
)

type Resource struct {
	ID        uuid.UUID       `db:"id"`
	Resource  json.RawMessage `db:"resource"`
	CreatedAt time.Time       `db:"created_at"`
	UpdatedAt time.Time       `db:"updated_at"`
}

func (Resource) TableName() string {
	return "scim_resources"
}
