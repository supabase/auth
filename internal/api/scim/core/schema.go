package core

import "time"

// Schema is the schema definition resource of RFC 7643, Section 7.
type Schema struct {
	Schemas     []SchemaURI      `json:"schemas"`
	ID          SchemaURI        `json:"id"`
	Name        ResourceTypeName `json:"name"`
	Description string           `json:"description"`
	Attributes  []*Attribute     `json:"attributes"`
	Meta        Meta             `json:"meta"`
}

func NewSchema(baseURL string, kind Kind) *Schema {
	schema := &Schema{
		Schemas: []SchemaURI{SchemaSchema},
		ID:      kind.Schema,
		Name:    kind.Name,
	}
	schema.Meta = NewMeta(baseURL, KindSchema).For(schema)

	return schema
}

func (s *Schema) Describe(description string) *Schema {
	s.Description = description
	return s
}

func (s *Schema) With(attributes ...*Attribute) *Schema {
	s.Attributes = attributes
	return s
}

func (s *Schema) ResourceID() string { return string(s.ID) }

func (s *Schema) Timestamps() (created, updated time.Time) { return }
