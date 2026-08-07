package core

// ServiceProviderConfig is the schema defined in RFC 7643, Section 5.
type ServiceProviderConfig struct {
	Schemas               []SchemaURI             `json:"schemas"`
	Patch                 SupportedFeature        `json:"patch"`
	Bulk                  BulkFeature             `json:"bulk"`
	Filter                FilterFeature           `json:"filter"`
	ChangePassword        SupportedFeature        `json:"changePassword"`
	Sort                  SupportedFeature        `json:"sort"`
	ETag                  SupportedFeature        `json:"etag"`
	AuthenticationSchemes []*AuthenticationScheme `json:"authenticationSchemes"`
	Meta                  Meta                    `json:"meta"`
}

func NewServiceProviderConfig(baseURL string, schemes ...*AuthenticationScheme) *ServiceProviderConfig {
	if schemes == nil {
		schemes = []*AuthenticationScheme{}
	}
	return &ServiceProviderConfig{
		Schemas:               []SchemaURI{SchemaServiceProviderConfig},
		AuthenticationSchemes: schemes,
		Meta:                  ResourceTypeServiceProviderConfig.Meta(baseURL),
	}
}
