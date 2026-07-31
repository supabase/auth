package core

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

// User is the core User resource defined in RFC 7643, Section 4.1.
type User struct {
	Schemas  []SchemaURI `json:"schemas"`
	ID       string      `json:"id"`
	UserName string      `json:"userName"`
	Emails   []Email     `json:"emails,omitempty"`
	Meta     Meta        `json:"meta"`
}
