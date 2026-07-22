package scim

type ServiceProviderConfiguration struct {
	Schemas          []string `json:"schemas"`
	DocumentationURI string   `json:"documentation_uri"`
}
