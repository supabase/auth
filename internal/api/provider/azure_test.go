package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAzureIssuer(t *testing.T) {
	positiveExamples := []string{
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/",
		"https://login.microsoftonline.com/common/v2.0",
	}

	negativeExamples := []string{
		"http://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0?something=else",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/extra",
	}

	for _, example := range positiveExamples {
		if !IsAzureIssuer(example) {
			t.Errorf("Example %q should be treated as a valid Azure issuer", example)
		}
	}

	for _, example := range negativeExamples {
		if IsAzureIssuer(example) {
			t.Errorf("Example %q should be treated as not a valid Azure issuer", example)
		}
	}
}

func TestAzureResolveIndirectClaims(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		w.Write([]byte(`{
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Collection(Edm.String)",
    "value": [
        "fee2c45b-915a-4a64-b130-f4eb9e75525e",
        "4fe90ae7-065a-478b-9400-e0a0e1cbd540",
        "c9ee2d50-9e8a-4352-b97c-4c2c99557c22",
        "e0c3beaf-eeb4-43d8-abc5-94f037a65697"
    ]
}`))
	}))

	defer server.Close()

	var claims AzureIDTokenClaims

	resolvedClaims, err := claims.ResolveIndirectClaims(context.Background(), server.Client(), "access-token")
	require.Nil(t, resolvedClaims)
	require.Nil(t, err)

	claims.ClaimNames = make(map[string]string)

	resolvedClaims, err = claims.ResolveIndirectClaims(context.Background(), server.Client(), "access-token")
	require.Nil(t, resolvedClaims)
	require.Nil(t, err)

	claims.ClaimNames = map[string]string{
		"groups":         "src1",
		"missing-source": "src2",
		"not-https":      "src3",
	}
	claims.ClaimSources = map[string]AzureIDTokenClaimSource{
		"src1": {
			Endpoint: server.URL,
		},
		"src3": {
			Endpoint: "http://example.com",
		},
	}

	resolvedClaims, err = claims.ResolveIndirectClaims(context.Background(), server.Client(), "access-token")
	require.NoError(t, err)
	require.NotNil(t, resolvedClaims)
	require.Equal(t, 1, len(resolvedClaims))
	require.Equal(t, 4, len(resolvedClaims["groups"].([]interface{})))
}

func TestAzureResolveIndirectClaimsFailures(t *testing.T) {
	examples := []struct {
		name          string
		urlSuffix     string
		statusCode    int
		body          []byte
		expectedError string
	}{
		{
			name:          "invalid url",
			urlSuffix:     "\000",
			expectedError: "azure: failed to create POST request to \"SERVER-URL\\x00\" (resolving overage claim \"groups\"): parse \"SERVER-URL\\x00\": net/url: invalid control character in URL",
		},
		{
			name:          "no such server",
			urlSuffix:     "000",
			expectedError: "azure: failed to send POST request to \"SERVER-URL000\" (resolving overage claim \"groups\"): Post \"SERVER-URL000\": dial tcp: address PORT000: invalid port",
		},
		{
			name:          "non 200 status code",
			statusCode:    500,
			body:          []byte(`something is wrong`),
			expectedError: "azure: received 500 but expected 200 HTTP status code when sending POST to \"SERVER-URL\" (resolving overage claim \"groups\") with response body \"something is wrong\"",
		},
		{
			name:          "non 200 status code, non utf8 valid body",
			statusCode:    201,
			body:          []byte{255, 255, 255, 255},
			expectedError: "azure: received 201 but expected 200 HTTP status code when sending POST to \"SERVER-URL\" (resolving overage claim \"groups\") with response body \"<invalid-utf8>\"",
		},
		{
			name:          "non 200 status code, empty body",
			statusCode:    201,
			body:          []byte{},
			expectedError: "azure: received 201 but expected 200 HTTP status code when sending POST to \"SERVER-URL\" (resolving overage claim \"groups\") with response body \"<empty>\"",
		},
		{
			name:          "non 200 status code, body over 2KB",
			statusCode:    201,
			body:          []byte(strings.Repeat("x", 2*1024+1)),
			expectedError: "azure: received 201 but expected 200 HTTP status code when sending POST to \"SERVER-URL\" (resolving overage claim \"groups\") with response body \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
		},
		{
			name:          "ok response, not json",
			statusCode:    200,
			body:          []byte("not json"),
			expectedError: "azure: failed to parse JSON response from POST to \"SERVER-URL\" (resolving overage claim \"groups\"): invalid character 'o' in literal null (expecting 'u')",
		},
	}

	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(example.statusCode)

				w.Write(example.body)
			}))

			defer server.Close()

			u, _ := url.Parse(server.URL)

			var claims AzureIDTokenClaims

			claims.ClaimNames = map[string]string{
				"groups": "src1",
			}
			claims.ClaimSources = map[string]AzureIDTokenClaimSource{
				"src1": {
					Endpoint: server.URL + example.urlSuffix,
				},
			}

			resolvedClaims, err := claims.ResolveIndirectClaims(context.Background(), server.Client(), "access-token")
			require.Nil(t, resolvedClaims)
			require.Error(t, err)
			require.Equal(t, example.expectedError, strings.ReplaceAll(strings.ReplaceAll(err.Error(), server.URL, "SERVER-URL"), u.Port(), "PORT"))
		})
	}

}
