package store

import (
	"encoding/json"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/api/scim/query"
)

type Row struct {
	Resource
	References json.RawMessage `db:"refs"`
}

func (r Row) Into[T core.Resource](endpoint string) (T, error) {
	var item T
	if err := json.Unmarshal(r.Resource.Resource, &item); err != nil {
		return item, err
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(r.References, &parts); err != nil {
		return item, err
	}
	for _, part := range parts {
		if string(part) == "null" {
			continue
		}
		if err := json.Unmarshal(part, &item); err != nil {
			return item, err
		}
	}
	common := item.Common()
	common.ID = r.ID.String()
	common.Meta = core.Meta{
		ResourceType: core.ResourceTypeName(r.ResourceType),
		Created:      r.CreatedAt.UTC(),
		LastModified: r.UpdatedAt.UTC(),
		Location:     endpoint + "/" + common.ID,
		Version:      query.Version(r.UpdatedAt),
	}
	return item, nil
}
