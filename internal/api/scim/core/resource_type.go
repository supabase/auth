package core

// ResourceType is the resource type metadata defined in RFC 7643, Section 6.
type ResourceType struct {
	Schemas     []SchemaURI      `json:"schemas"`
	ID          ResourceTypeName `json:"id"`
	Name        ResourceTypeName `json:"name"`
	Description string           `json:"description,omitempty"`
	Endpoint    string           `json:"endpoint"`
	Schema      SchemaURI        `json:"schema"`
	Meta        Meta             `json:"meta"`
}

// NewResourceType builds the resource type describing schema, served at
// endpoint. Taking the schema rather than its URI is what makes RFC 7643,
// Section 6 hold by construction: the resource type's schema attribute "MUST
// be equal to the id attribute of the associated Schema resource".
func NewResourceType(baseURL string, schema *Schema, endpoint string) *ResourceType {
	return &ResourceType{
		Schemas:     []SchemaURI{SchemaResourceType},
		ID:          schema.Name,
		Name:        schema.Name,
		Description: schema.Description,
		Endpoint:    endpoint,
		Schema:      schema.ID,
		Meta:        NewMeta(baseURL, ResourceTypeResourceType, EndpointResourceTypes, string(schema.Name)),
	}
}

func (r *ResourceType) Describe(description string) *ResourceType {
	r.Description = description
	return r
}
