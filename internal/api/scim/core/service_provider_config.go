// Package core implements the SCIM 2.0 core schema defined in RFC 7643.
package core

type BulkFeature struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type FilterFeature struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type SupportedFeature struct {
	Supported bool `json:"supported"`
}

type AuthenticationScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SpecURI     string `json:"specUri,omitempty"`
	Primary     bool   `json:"primary"`
}

// OAuthBearerToken is the scheme described in RFC 7643, Section 8.5.
func OAuthBearerToken() AuthenticationScheme {
	return AuthenticationScheme{
		Type:        "oauthbearertoken",
		Name:        "OAuth Bearer Token",
		Description: "Authentication scheme using the OAuth Bearer Token Standard",
		SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
	}
}

func (scheme AuthenticationScheme) AsPrimary() AuthenticationScheme {
	scheme.Primary = true
	return scheme
}

type ServiceProviderConfig struct {
	Schemas               []string               `json:"schemas"`
	Patch                 SupportedFeature       `json:"patch"`
	Bulk                  BulkFeature            `json:"bulk"`
	Filter                FilterFeature          `json:"filter"`
	ChangePassword        SupportedFeature       `json:"changePassword"`
	Sort                  SupportedFeature       `json:"sort"`
	ETag                  SupportedFeature       `json:"etag"`
	AuthenticationSchemes []AuthenticationScheme `json:"authenticationSchemes"`
	Meta                  Meta                   `json:"meta"`
}

func NewServiceProviderConfig(baseURL string, schemes []AuthenticationScheme) *ServiceProviderConfig {
	return &ServiceProviderConfig{
		Schemas:               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		AuthenticationSchemes: append(make([]AuthenticationScheme, 0, len(schemes)), schemes...),
		Meta: Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     baseURL + "/ServiceProviderConfig",
		},
	}
}
