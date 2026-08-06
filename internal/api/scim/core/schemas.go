package core

// The schema URIs of RFC 7643
const (
	schemaRoot = "urn:ietf:params:scim:schemas"
	schemaCore = schemaRoot + ":core:2.0"

	SchemaGroup                 SchemaURI = schemaCore + ":Group"
	SchemaResourceType          SchemaURI = schemaCore + ":ResourceType"
	SchemaSchema                SchemaURI = schemaCore + ":Schema"
	SchemaServiceProviderConfig SchemaURI = schemaCore + ":ServiceProviderConfig"
	SchemaUser                  SchemaURI = schemaCore + ":User"
)

const (
	ResourceTypeGroup                 ResourceTypeName = "Group"
	ResourceTypeResourceType          ResourceTypeName = "ResourceType"
	ResourceTypeSchema                ResourceTypeName = "Schema"
	ResourceTypeServiceProviderConfig ResourceTypeName = "ServiceProviderConfig"
	ResourceTypeUser                  ResourceTypeName = "User"
)
