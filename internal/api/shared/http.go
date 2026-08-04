package shared

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
)

// SendJSON sends a JSON response with proper error handling
func SendJSON(w http.ResponseWriter, status int, obj any) error {
	return SendJSONAs(w, status, "application/json", obj)
}

func SendJSONAs(w http.ResponseWriter, status int, contentType string, obj any) error {
	var b []byte
	if obj != nil {
		var err error
		b, err = json.Marshal(obj)
		if err != nil {
			return errors.Wrapf(err, "Error encoding json response: %v", obj)
		}
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, err := w.Write(b)
	return err
}
