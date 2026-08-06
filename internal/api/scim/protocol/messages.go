package protocol

// The message URIs of RFC 7644, composed from the registered URN namespace so
// the prefix is declared once.
const (
	messagesRoot = "urn:ietf:params:scim:api:messages:2.0"

	SchemaBulkRequest   = messagesRoot + ":BulkRequest"
	SchemaBulkResponse  = messagesRoot + ":BulkResponse"
	SchemaError         = messagesRoot + ":Error"
	SchemaListResponse  = messagesRoot + ":ListResponse"
	SchemaPatchOp       = messagesRoot + ":PatchOp"
	SchemaSearchRequest = messagesRoot + ":SearchRequest"
)
