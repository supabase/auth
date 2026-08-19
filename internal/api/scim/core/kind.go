package core

import "strings"

type Kind struct {
	Name     ResourceTypeName
	Endpoint string
}

var (
	KindGroup                 = Kind{Name: "Group", Endpoint: "/Groups"}
	KindResourceType          = Kind{Name: "ResourceType", Endpoint: "/ResourceTypes"}
	KindSchema                = Kind{Name: "Schema", Endpoint: "/Schemas"}
	KindServiceProviderConfig = Kind{Name: "ServiceProviderConfig", Endpoint: "/ServiceProviderConfig"}
	KindUser                  = Kind{Name: "User", Endpoint: "/Users"}
)

func (k Kind) Location(baseURL string) string {
	return Join(baseURL, k.Endpoint)
}

func Join(base, segment string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(segment, "/")
}
