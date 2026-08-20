package core

import "strings"

type Kind struct {
	Name     ResourceTypeName
	Schema   SchemaURI
	Endpoint string
}

var (
	KindGroup                 = Kind{Name: "Group", Schema: SchemaGroup, Endpoint: "/Groups"}
	KindResourceType          = Kind{Name: "ResourceType", Schema: SchemaResourceType, Endpoint: "/ResourceTypes"}
	KindSchema                = Kind{Name: "Schema", Schema: SchemaSchema, Endpoint: "/Schemas"}
	KindServiceProviderConfig = Kind{Name: "ServiceProviderConfig", Schema: SchemaServiceProviderConfig, Endpoint: "/ServiceProviderConfig"}
	KindUser                  = Kind{Name: "User", Schema: SchemaUser, Endpoint: "/Users"}
)

func (k Kind) Location(baseURL string) string {
	return Join(baseURL, k.Endpoint)
}

func Join(base, segment string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(segment, "/")
}
