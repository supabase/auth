package scim

const schemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

type ListResponse[T any] struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []T      `json:"Resources"`
}

func NewListResponse[T any](resources []T) *ListResponse[T] {
	if resources == nil {
		resources = []T{}
	}
	return &ListResponse[T]{
		Schemas:      []string{schemaListResponse},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}
