package oauthserver

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// ExtractClientCredentials extracts OAuth client credentials from the request
// Supports both Basic auth header and form body parameters
func ExtractClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	// First, try Basic auth header: Authorization: Basic base64(client_id:client_secret)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", errors.New("invalid basic auth encoding")
		}

		credentials := string(decoded)
		parts := strings.SplitN(credentials, ":", 2)
		if len(parts) != 2 {
			return "", "", errors.New("invalid basic auth format")
		}

		return parts[0], parts[1], nil
	}

	// Fall back to form parameters
	if err := r.ParseForm(); err != nil {
		return "", "", errors.New("failed to parse form")
	}

	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")

	// Return empty credentials if both are empty (no client auth attempted)
	if clientID == "" && clientSecret == "" {
		return "", "", nil
	}

	// For public clients, only client_id is required (client_secret should be empty)
	// For confidential clients, both client_id and client_secret are required
	// We'll validate this based on the client type in the calling handler
	// TODO(cemal) :: this will be validated in detail during the `/token` endpoint implementation
	if clientID == "" {
		return "", "", errors.New("client_id is required")
	}

	return clientID, clientSecret, nil
}
