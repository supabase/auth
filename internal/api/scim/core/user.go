package core

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

// Name holds the components of the user's name, per RFC 7643, Section 4.1.1.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
}

// User is the core User resource defined in RFC 7643, Section 4.1.
type User struct {
	Schemas    []SchemaURI `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       Name        `json:"name,omitzero"`
	Emails     []Email     `json:"emails,omitempty"`
	Active     *bool       `json:"active,omitempty"`
	Meta       Meta        `json:"meta"`
}
