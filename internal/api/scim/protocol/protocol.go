package protocol

import (
	"net/http"

	"github.com/supabase/auth/internal/api/shared"
)

// MediaType is the SCIM media type defined in RFC 7644, Section 3.1.
const MediaType = "application/scim+json"

// Send writes obj as a SCIM response body.
func Send(w http.ResponseWriter, status int, obj any) error {
	return shared.SendJSONAs(w, status, MediaType, obj)
}
