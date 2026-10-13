package store

import (
	"encoding/json"
	"strconv"
	"time"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
)

type Resource struct {
	ID            uuid.UUID       `db:"id"`
	SSOProviderID uuid.UUID       `db:"sso_provider_id"`
	ResourceType  string          `db:"resource_type"`
	Resource      json.RawMessage `db:"resource"`
	CreatedAt     time.Time       `db:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"`
	DeletedAt     *time.Time      `db:"deleted_at"`
}

func (Resource) TableName() string {
	return "scim_resources"
}

func (r Resource) As[T core.Resource](endpoint string) (T, error) {
	var item T
	if err := json.Unmarshal(r.Resource, &item); err != nil {
		return item, err
	}
	common := item.Common()
	common.ID = r.ID.String()
	common.Meta = core.Meta{
		ResourceType: core.ResourceTypeName(r.ResourceType),
		Created:      r.CreatedAt.UTC(),
		LastModified: r.UpdatedAt.UTC(),
		Location:     endpoint + "/" + common.ID,
		Version:      `W/"` + strconv.FormatInt(r.UpdatedAt.UnixMicro(), 10) + `"`,
	}
	return item, nil
}
