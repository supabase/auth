package core

import "time"

type Meta struct {
	ResourceType ResourceTypeName `json:"resourceType"`
	Created      time.Time        `json:"created,omitzero"`
	LastModified time.Time        `json:"lastModified,omitzero"`
	Location     string           `json:"location,omitempty"`
}

func NewMeta(baseURL string, resourceType ResourceType) Meta {
	return resourceType.Meta(baseURL)
}

func (m Meta) For(r Resource) Meta {
	created, updated := r.Timestamps()

	m.Location += "/" + r.ResourceID()
	m.Created, m.LastModified = created.UTC(), updated.UTC()

	return m
}
