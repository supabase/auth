package core

type AuthenticationSchemeType string

const (
	AuthenticationSchemeOAuthBearerToken AuthenticationSchemeType = "oauthbearertoken"
)

type AuthenticationScheme struct {
	Type        AuthenticationSchemeType `json:"type"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	SpecURI     string                   `json:"specUri,omitempty"`
	Primary     bool                     `json:"primary"`
}

func NewOAuthBearerToken() *AuthenticationScheme {
	return &AuthenticationScheme{
		Type:        AuthenticationSchemeOAuthBearerToken,
		Name:        "OAuth Bearer Token",
		Description: "Authentication scheme using the OAuth Bearer Token Standard",
		SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
	}
}

func (scheme *AuthenticationScheme) AsPrimary() *AuthenticationScheme {
	scheme.Primary = true
	return scheme
}
