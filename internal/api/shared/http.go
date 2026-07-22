package shared

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// SendJSON sends a JSON response with proper error handling
func SendJSON(w http.ResponseWriter, status int, obj any) error {
	return SendJSONAs(w, status, "application/json", obj)
}

// SendJSONAs sends a JSON response with proper error handling, using the
// given Content-Type instead of the standard "application/json" (e.g. for
// SCIM's "application/scim+json"). obj is marshaled before anything is
// written to w, so a marshal failure never leaves a status/body already
// committed with no way to report it correctly.
func SendJSONAs[T any](w http.ResponseWriter, status int, contentType string, obj T) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error encoding json response: %v", obj))
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}
