package core

type SupportedFeature struct {
	Supported bool `json:"supported"`
}

type BulkFeature struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type FilterFeature struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type AuthenticationSchemeType string

// The authentication scheme types of RFC 7643, Section 5.
const (
	AuthenticationSchemeOAuth            AuthenticationSchemeType = "oauth"
	AuthenticationSchemeOAuth2           AuthenticationSchemeType = "oauth2"
	AuthenticationSchemeOAuthBearerToken AuthenticationSchemeType = "oauthbearertoken"
	AuthenticationSchemeHTTPBasic        AuthenticationSchemeType = "httpbasic"
	AuthenticationSchemeHTTPDigest       AuthenticationSchemeType = "httpdigest"
)

type AuthenticationScheme struct {
	Type             AuthenticationSchemeType `json:"type"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	SpecURI          string                   `json:"specUri,omitempty"`
	DocumentationURI string                   `json:"documentationUri,omitempty"`
	Primary          bool                     `json:"primary"`
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

// ServiceProviderConfig is the schema defined in RFC 7643, Section 5.
type ServiceProviderConfig struct {
	Schemas               []SchemaURI             `json:"schemas"`
	DocumentationURI      string                  `json:"documentationUri,omitempty"`
	Patch                 SupportedFeature        `json:"patch"`
	Bulk                  BulkFeature             `json:"bulk"`
	Filter                FilterFeature           `json:"filter"`
	ChangePassword        SupportedFeature        `json:"changePassword"`
	Sort                  SupportedFeature        `json:"sort"`
	ETag                  SupportedFeature        `json:"etag"`
	AuthenticationSchemes []*AuthenticationScheme `json:"authenticationSchemes"`
	Meta                  Meta                    `json:"meta"`
}

// Sorting states that this provider honours the "sortBy" and "sortOrder"
// parameters of RFC 7644, Section 3.4.2.3. A provider may still refuse to order
// by a particular attribute, answering "invalidValue"; what it claims here is
// that asking is meaningful.
func (c *ServiceProviderConfig) Sorting() *ServiceProviderConfig {
	c.Sort.Supported = true
	return c
}

// Filtering states that this provider honours the "filter" parameter of RFC
// 7644, Section 3.4.2.2, and the largest number of results a filter may return,
// which is this provider's page bound. A provider may still refuse a particular
// filter, answering "invalidFilter"; what it claims here is that filtering is
// meaningful.
func (c *ServiceProviderConfig) Filtering(maxResults int) *ServiceProviderConfig {
	c.Filter.Supported = true
	c.Filter.MaxResults = maxResults
	return c
}

// Patching states that this provider honours the PATCH request of RFC 7644,
// Section 3.5.2.
func (c *ServiceProviderConfig) Patching() *ServiceProviderConfig {
	c.Patch.Supported = true
	return c
}

func NewServiceProviderConfig(baseURL string, schemes ...*AuthenticationScheme) *ServiceProviderConfig {
	if schemes == nil {
		schemes = []*AuthenticationScheme{}
	}
	return &ServiceProviderConfig{
		Schemas:               []SchemaURI{SchemaServiceProviderConfig},
		AuthenticationSchemes: schemes,
		Meta:                  NewMeta(baseURL, KindServiceProviderConfig),
	}
}
