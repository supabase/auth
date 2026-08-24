package protocol

import "github.com/supabase/auth/internal/api/scim/core"

// ListResponse is the query response of RFC 7644, Section 3.4.2.
type ListResponse[T any] struct {
	Schemas      []core.SchemaURI `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []T              `json:"Resources"`
}

// NewListResponse describes one page of a collection: the resources in the
// window the client asked for, and the number of resources its query matched.
func NewListResponse[T any](startIndex, total int, resources []T) *ListResponse[T] {
	if resources == nil {
		resources = []T{}
	}

	return &ListResponse[T]{
		Schemas:      []core.SchemaURI{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}
