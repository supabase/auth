package core

import "time"

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

// Name is the complex name attribute of RFC 7643, Section 4.1.1.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// User is the core User resource defined in RFC 7643, Section 4.1.
type User struct {
	Schemas    []SchemaURI `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       *Name       `json:"name,omitempty"`
	Emails     []Email     `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       Meta        `json:"meta"`
}

func NewUser(baseURL, id, userName string, active bool) *User {
	return &User{
		Schemas:  []SchemaURI{SchemaUser},
		ID:       id,
		UserName: userName,
		Active:   active,
		Meta:     NewMeta(baseURL, ResourceTypeUser, EndpointUsers, id),
	}
}

func (u *User) Named(name Name) *User {
	u.Name = &name
	return u
}

func (u *User) WithEmails(emails ...Email) *User {
	u.Emails = emails
	return u
}

func (u *User) WithExternalID(externalID string) *User {
	u.ExternalID = externalID
	return u
}

func (u *User) At(created, lastModified time.Time) *User {
	u.Meta.Created, u.Meta.LastModified = created, lastModified
	return u
}
