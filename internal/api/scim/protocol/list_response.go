package protocol

import "github.com/supabase/auth/internal/api/scim/core"

type ListResponse[T any] struct {
	Schemas      []core.SchemaURI `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []T              `json:"Resources"`
}

func NewPage[T any](resources []T, startIndex, totalResults int) *ListResponse[T] {
	if resources == nil {
		resources = []T{}
	}
	return &ListResponse[T]{
		Schemas:      []core.SchemaURI{SchemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}

func NewListResponse[T any](resources []T) *ListResponse[T] {
	return NewPage(resources, 1, len(resources))
}
