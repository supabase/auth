package oauthserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ExtractClientCredentials extracts OAuth client credentials from the request
// Supports Basic auth header, form body parameters, and JSON body parameters
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

	// Check Content-Type to determine how to parse body parameters
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// Parse JSON body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", "", errors.New("failed to read request body")
		}
		// Restore the body so other handlers can read it
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		var jsonData struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			return "", "", errors.New("failed to parse JSON body")
		}

		clientID = jsonData.ClientID
		clientSecret = jsonData.ClientSecret
	} else {
		// Fall back to form parameters
		if err := r.ParseForm(); err != nil {
			return "", "", errors.New("failed to parse form")
		}

		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	// return error if client_id is not provided
	if clientID == "" {
		return "", "", errors.New("client_id is required")
	}

	return clientID, clientSecret, nil
}
