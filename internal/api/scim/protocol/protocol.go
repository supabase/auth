// Package protocol implements the SCIM 2.0 protocol defined in RFC 7644.
package protocol

import (
	"net/http"

	"github.com/supabase/auth/internal/api/shared"
)

const MediaType = "application/scim+json"

func Send(w http.ResponseWriter, status int, obj any) error {
	return shared.SendJSONAs(w, status, MediaType, obj)
}
