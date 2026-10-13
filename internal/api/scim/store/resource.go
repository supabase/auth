package store

import (
	"encoding/json"
	"time"
	"uuid"
)

type Resource struct {
	ID           uuid.UUID       `db:"id"`
	ResourceType string          `db:"resource_type"`
	Resource     json.RawMessage `db:"resource"`
	CreatedAt    time.Time       `db:"created_at"`
	UpdatedAt    time.Time       `db:"updated_at"`
}

func (Resource) TableName() string {
	return "scim_resources"
}
