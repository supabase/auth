package core

// The schema URIs of RFC 7643
const (
	schemaRoot      = "urn:ietf:params:scim:schemas"
	schemaCore      = schemaRoot + ":core:2.0"
	schemaExtension = schemaRoot + ":extension"

	SchemaEnterpriseUser SchemaURI = schemaExtension + ":enterprise:2.0:User"

	SchemaGroup                 SchemaURI = schemaCore + ":Group"
	SchemaResourceType          SchemaURI = schemaCore + ":ResourceType"
	SchemaSchema                SchemaURI = schemaCore + ":Schema"
	SchemaServiceProviderConfig SchemaURI = schemaCore + ":ServiceProviderConfig"
	SchemaUser                  SchemaURI = schemaCore + ":User"
)
