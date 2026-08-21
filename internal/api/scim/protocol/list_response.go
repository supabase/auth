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
//
// total is asked for separately because it is not len(resources): a client
// pages through a collection larger than the page it is holding, and a total
// taken from the page would tell it there is nothing more to fetch. A caller
// holding a whole collection states that, as in NewListResponse(1, len(all), all).
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
