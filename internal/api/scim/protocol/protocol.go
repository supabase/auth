// Package protocol implements the SCIM 2.0 protocol defined in RFC 7644.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// MediaType is the SCIM media type registered in RFC 7644, Section 8.1.
const MediaType = "application/scim+json"

// Send writes obj as a SCIM response.
func Send(w http.ResponseWriter, status int, obj any) error {
	var body []byte
	if obj != nil {
		var err error
		if body, err = json.Marshal(obj); err != nil {
			return fmt.Errorf("scim: encoding %T: %w", obj, err)
		}
	}

	w.Header().Set("Content-Type", MediaType)
	w.WriteHeader(status)

	if len(body) == 0 {
		return nil
	}

	_, err := w.Write(body)
	return err
}

// WriteError answers the request with err in the error form of RFC 7644, Section 3.12.
func WriteError(w http.ResponseWriter, err error) error {
	var scimErr *Error
	if !errors.As(err, &scimErr) {
		scimErr = ErrInternal("Internal server error")
	}

	return Send(w, scimErr.StatusCode(), scimErr)
}
