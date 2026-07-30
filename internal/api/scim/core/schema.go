package core

// Schema is the schema definition resource of RFC 7643, Section 7.
type Schema struct {
	Schemas     []SchemaURI      `json:"schemas"`
	ID          SchemaURI        `json:"id"`
	Name        ResourceTypeName `json:"name"`
	Description string           `json:"description"`
	Attributes  []*Attribute     `json:"attributes"`
	Meta        Meta             `json:"meta"`
}

// NewSchema builds the schema definition resource for id. Attributes and
// description are optional and set with With and Describe.
func NewSchema(baseURL string, id SchemaURI, name ResourceTypeName) *Schema {
	return &Schema{
		Schemas: []SchemaURI{SchemaSchema},
		ID:      id,
		Name:    name,
		Meta:    NewMeta(baseURL, ResourceTypeSchema, EndpointSchemas, string(id)),
	}
}

func (s *Schema) Describe(description string) *Schema {
	s.Description = description
	return s
}

func (s *Schema) With(attributes ...*Attribute) *Schema {
	s.Attributes = attributes
	return s
}
