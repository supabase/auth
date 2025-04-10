package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
)

type TokenOIDCTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestTokenOIDC(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &TokenOIDCTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func SetupTestOIDCProvider(ts *TokenOIDCTestSuite) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"issuer":"` + server.URL + `","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","jwks_uri":"` + server.URL + `/jwks"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func (ts *TokenOIDCTestSuite) TestGetProvider() {
	server := SetupTestOIDCProvider(ts)
	defer server.Close()

	params := &IdTokenGrantParams{
		IdToken:     "test-id-token",
		AccessToken: "test-access-token",
		Nonce:       "test-nonce",
		Provider:    server.URL,
		ClientID:    "test-client-id",
		Issuer:      server.URL,
	}

	ts.Config.External.AllowedIdTokenIssuers = []string{server.URL}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	oidcProvider, skipNonceCheck, providerType, acceptableClientIds, err := params.getProvider(context.Background(), ts.Config, req)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), oidcProvider)
	require.False(ts.T(), skipNonceCheck)
	require.Equal(ts.T(), params.Provider, providerType)
	require.NotEmpty(ts.T(), acceptableClientIds)
}
