package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchSAMLMetadataReturnsBody(t *testing.T) {
	body := `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity"/>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	data, err := fetchSAMLMetadata(context.Background(), server.URL)
	require.NoError(t, err)
	require.Equal(t, body, string(data))
}

func TestFetchSAMLMetadataRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxSAMLMetadataSize+1)))
	}))
	defer server.Close()

	_, err := fetchSAMLMetadata(context.Background(), server.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds the maximum size")
}

func TestFetchSAMLMetadataReturnsGzippedBody(t *testing.T) {
	body := `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity"/>`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(body))
	require.NoError(t, gz.Close())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer server.Close()

	data, err := fetchSAMLMetadata(context.Background(), server.URL)
	require.NoError(t, err)
	require.Equal(t, body, string(data))
}

func TestFetchSAMLMetadataTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	oldTimeout := samlMetadataFetchTimeout
	samlMetadataFetchTimeout = 100 * time.Millisecond
	defer func() {
		samlMetadataFetchTimeout = oldTimeout
	}()

	start := time.Now()
	_, err := fetchSAMLMetadata(context.Background(), server.URL)
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}
