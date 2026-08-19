package core

import "time"

// Meta is the resource metadata common attribute defined in RFC 7643, Section 3.1.
type Meta struct {
	ResourceType ResourceTypeName `json:"resourceType"`
	Created      time.Time        `json:"created,omitzero"`
	LastModified time.Time        `json:"lastModified,omitzero"`
	Location     string           `json:"location,omitempty"`
	Version      string           `json:"version,omitempty"`
}

func NewMeta(baseURL string, kind Kind) Meta {
	return Meta{
		ResourceType: kind.Name,
		Location:     kind.Location(baseURL),
	}
}

func NewMetaFor(baseURL string, kind Kind, r Resource) Meta {
	created, updated := r.Timestamps()
	return NewMetaForID(baseURL, kind, r.ResourceID(), created, updated)
}

func NewMetaForID(baseURL string, kind Kind, id string, created, updated time.Time) Meta {
	meta := NewMeta(baseURL, kind)
	meta.Location = Join(meta.Location, id)
	meta.Created, meta.LastModified = created.UTC(), updated.UTC()

	return meta
}
