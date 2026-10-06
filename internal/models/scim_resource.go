package models

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
)

type SCIMResource struct {
	ID            uuid.UUID       `db:"id"`
	SSOProviderID uuid.UUID       `db:"sso_provider_id"`
	ResourceType  string          `db:"resource_type"`
	Resource      json.RawMessage `db:"resource"`
	CreatedAt     time.Time       `db:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at"`
	DeletedAt     *time.Time      `db:"deleted_at"`
}

func (SCIMResource) TableName() string {
	return "scim_resources"
}

func (r SCIMResource) As[T core.Resource](endpoint string) (T, error) {
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

func scimVersionTime(version string) *time.Time {
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil
	}
	t := time.UnixMicro(micros).UTC()
	return &t
}
