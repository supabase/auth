package shared

import (
	"net/http"
	"strings"
)

const bearerScheme = "bearer "

// SendJSON sends a JSON response with proper error handling
func SendJSON(w http.ResponseWriter, status int, obj any) error {
	return JSON(w).ContentType("application/json").Status(status).Send(obj)
}

// Parses the bearer token a client authenticates with, per RFC 6750, Section 2.1.
func Credential(r *http.Request) string {
	header := r.Header.Get("Authorization")

	if len(header) < len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerScheme):])
}
