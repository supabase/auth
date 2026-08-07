package core

var (
	ResourceTypeServiceProviderConfig = ResourceType{
		Name:     "ServiceProviderConfig",
		Endpoint: "/ServiceProviderConfig",
	}

	ResourceTypeUser = ResourceType{
		Name:     "User",
		Endpoint: "/Users",
	}
)

type ResourceTypeName string

type ResourceType struct {
	Name     ResourceTypeName
	Endpoint string
}

func (r ResourceType) Meta(baseURL string) Meta {
	return Meta{
		ResourceType: r.Name,
		Location:     r.Location(baseURL),
	}
}

func (r ResourceType) Location(baseURL string) string {
	return baseURL + r.Endpoint
}
