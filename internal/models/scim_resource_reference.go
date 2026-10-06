package models

import (
	"github.com/gofrs/uuid"
)

type SCIMReference struct {
	SourceID   uuid.UUID `db:"source_id"`
	TargetID   uuid.UUID `db:"target_id"`
	TargetType string    `db:"target_type"`
}

func (SCIMReference) TableName() string {
	return "scim_resource_references"
}
