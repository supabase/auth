package core

// Meta is the resource metadata common attribute defined in RFC 7643, Section 3.1.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}
