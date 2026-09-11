package scim

import (
	"errors"
	"net/http"

	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/observability"
)

func NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, protocol.ErrNotFound("Endpoint or resource does not exist"))
}

func sendError(w http.ResponseWriter, r *http.Request, err error) error {
	if scimErr, ok := errors.AsType[*protocol.Error](err); ok {
		return protocol.SendError(w, scimErr)
	}
	return internalError(w, r, err)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.SendError(w, protocol.ErrInternal("Internal server error"))
}

func unauthorized(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	return protocol.SendError(w, protocol.ErrUnauthorized("Bearer token is missing or invalid"))
}

func rejectFilter(w http.ResponseWriter, r *http.Request, unsupported *protocol.Error) (bool, error) {
	if !r.URL.Query().Has("filter") {
		return false, nil
	}
	return true, protocol.SendError(w, unsupported)
}
