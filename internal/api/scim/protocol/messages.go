package protocol

import "github.com/supabase/auth/internal/api/scim/core"

// The message URIs of RFC 7644
const (
	messagesRoot = "urn:ietf:params:scim:api:messages:2.0"

	SchemaBulkRequest   core.SchemaURI = messagesRoot + ":BulkRequest"
	SchemaBulkResponse  core.SchemaURI = messagesRoot + ":BulkResponse"
	SchemaError         core.SchemaURI = messagesRoot + ":Error"
	SchemaListResponse  core.SchemaURI = messagesRoot + ":ListResponse"
	SchemaPatchOp       core.SchemaURI = messagesRoot + ":PatchOp"
	SchemaSearchRequest core.SchemaURI = messagesRoot + ":SearchRequest"
)
