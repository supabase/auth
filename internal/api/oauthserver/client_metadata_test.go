package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

const testCIMDRedirectURI = "https://example.com/callback"

// documentServer serves Client ID Metadata Documents over TLS and counts requests per path
type documentServer struct {
	*httptest.Server

	mu   sync.Mutex
	hits map[string]int
}

func newDocumentServer(t *testing.T, routes map[string]func(w http.ResponseWriter, clientID string)) *documentServer {
	ds := &documentServer{hits: map[string]int{}}
	ds.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ds.mu.Lock()
		ds.hits[r.URL.Path]++
		ds.mu.Unlock()

		route, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		route(w, "https://"+r.Host+r.URL.Path)
	}))
	t.Cleanup(ds.Close)
	return ds
}

func (ds *documentServer) url(path string) string {
	return ds.URL + path
}

func (ds *documentServer) hitCount(path string) int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.hits[path]
}

// jsonDocument serves a valid metadata document, optionally modified, with
// extra headers given as name/value pairs
func jsonDocument(modify func(doc map[string]any), headers ...string) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, clientID string) {
		doc := map[string]any{
			"client_id":                  clientID,
			"client_name":                "Test MCP Client",
			"client_uri":                 "https://client.example.com",
			"redirect_uris":              []string{testCIMDRedirectURI},
			"token_endpoint_auth_method": "none",
		}
		if modify != nil {
			modify(doc)
		}
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		_ = json.NewEncoder(w).Encode(doc)
	}
}

// ---------- client_id URL validation ----------

func TestValidateClientIDURL(t *testing.T) {
	valid := []string{
		"https://client.example.com/oauth/client.json",
		"https://client.example.com:8443/client",
		"https://claude.ai/oauth/claude-code-client-metadata",
	}
	for _, clientIDURL := range valid {
		assert.NoError(t, validateClientIDURL(clientIDURL, nil), clientIDURL)
	}

	invalid := map[string]string{
		"http://client.example.com/client.json":                   "must use https",
		"https://user:pass@client.example.com/c.json":             "user info",
		"https://client.example.com":                              "must contain a path",
		"https://client.example.com/":                             "must contain a path",
		"https://client.example.com/a/./client.json":              "dot path segments",
		"https://client.example.com/a/../client.json":             "dot path segments",
		"https://client.example.com/a/%2e%2e/client.json":         "dot path segments",
		"https://client.example.com/client.json#frag":             "fragment",
		"https://client.example.com/client.json?a=b":              "query",
		"https://client.example.com/client.json?":                 "query",
		"https://client.example.com/" + strings.Repeat("a", 2048): "at most 2048",
	}
	for clientIDURL, reason := range invalid {
		err := validateClientIDURL(clientIDURL, nil)
		require.Error(t, err, clientIDURL)
		assert.Contains(t, err.Error(), reason, clientIDURL)
	}

	allowed := []string{"Claude.ai"}
	assert.NoError(t, validateClientIDURL("https://claude.ai/oauth/client", allowed))
	assert.NoError(t, validateClientIDURL("https://CLAUDE.AI/oauth/client", allowed))
	err := validateClientIDURL("https://client.example.com/client.json", allowed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host is not allowed")
}

func TestIsSpecialUseAddr(t *testing.T) {
	special := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "192.0.2.10", "198.18.0.1", "224.0.0.1",
		"255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "2001:db8::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
	}
	for _, s := range special {
		assert.True(t, isSpecialUseAddr(netip.MustParseAddr(s)), s)
	}

	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range public {
		assert.False(t, isSpecialUseAddr(netip.MustParseAddr(s)), s)
	}
}

func TestClientMetadataCacheTTL(t *testing.T) {
	cases := map[string]time.Duration{
		"":                     clientMetadataDefaultTTL,
		"public":               clientMetadataDefaultTTL,
		"max-age=60":           time.Minute,
		"public, max-age=120":  2 * time.Minute,
		"max-age=0":            0,
		"no-store":             0,
		"no-cache, max-age=60": 0,
		"max-age=31536000":     clientMetadataMaxTTL,
		"max-age=not-a-number": 0,
	}
	for cacheControl, expected := range cases {
		header := http.Header{}
		if cacheControl != "" {
			header.Set("Cache-Control", cacheControl)
		}
		assert.Equal(t, expected, clientMetadataCacheTTL(header), cacheControl)
	}
}

// ---------- fetching ----------

func TestClientMetadataFetcher(t *testing.T) {
	var flakyCalls int
	ds := newDocumentServer(t, map[string]func(http.ResponseWriter, string){
		"/valid.json":     jsonDocument(nil),
		"/max-age.json":   jsonDocument(nil, "Cache-Control", "public, max-age=60"),
		"/no-store.json":  jsonDocument(nil, "Cache-Control", "no-store"),
		"/plus-json.json": jsonDocument(nil, "Content-Type", "application/oauth-client+json"),
		"/flaky.json": func(w http.ResponseWriter, clientID string) {
			flakyCalls++
			if flakyCalls == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			jsonDocument(nil)(w, clientID)
		},
		"/redirect.json": func(w http.ResponseWriter, _ string) {
			w.Header().Set("Location", "/valid.json")
			w.WriteHeader(http.StatusFound)
		},
		"/mismatch.json": jsonDocument(func(doc map[string]any) {
			doc["client_id"] = "https://other.example.com/client.json"
		}),
		"/secret.json": jsonDocument(func(doc map[string]any) {
			doc["client_secret"] = "s3cret"
		}),
		"/secret-auth.json": jsonDocument(func(doc map[string]any) {
			doc["token_endpoint_auth_method"] = "client_secret_basic"
		}),
		"/no-redirect-uris.json": jsonDocument(func(doc map[string]any) {
			delete(doc, "redirect_uris")
		}),
		"/bad-grant.json": jsonDocument(func(doc map[string]any) {
			doc["grant_types"] = []string{"implicit"}
		}),
		"/text.json": jsonDocument(nil, "Content-Type", "text/plain"),
		"/large.json": jsonDocument(func(doc map[string]any) {
			doc["client_name"] = strings.Repeat("a", clientMetadataMaxSize)
		}),
		"/invalid-json.json": func(w http.ResponseWriter, _ string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not json"))
		},
	})

	newFetcher := func() (*clientMetadataFetcher, *time.Time) {
		f := newClientMetadataFetcher(ds.Client())
		now := time.Now()
		f.now = func() time.Time { return now }
		return f, &now
	}
	ctx := context.Background()

	t.Run("valid document is parsed and cached", func(t *testing.T) {
		f, now := newFetcher()

		doc, err := f.fetch(ctx, ds.url("/valid.json"))
		require.NoError(t, err)
		assert.Equal(t, ds.url("/valid.json"), doc.ClientID)
		assert.Equal(t, "Test MCP Client", doc.ClientName)
		assert.Equal(t, []string{testCIMDRedirectURI}, doc.RedirectURIs)

		_, err = f.fetch(ctx, ds.url("/valid.json"))
		require.NoError(t, err)
		assert.Equal(t, 1, ds.hitCount("/valid.json"), "second fetch should use the cache")

		*now = now.Add(clientMetadataDefaultTTL + time.Second)
		_, err = f.fetch(ctx, ds.url("/valid.json"))
		require.NoError(t, err)
		assert.Equal(t, 2, ds.hitCount("/valid.json"), "expired entry should be fetched again")
	})

	t.Run("Cache-Control max-age is honored", func(t *testing.T) {
		f, now := newFetcher()

		_, err := f.fetch(ctx, ds.url("/max-age.json"))
		require.NoError(t, err)
		*now = now.Add(59 * time.Second)
		_, err = f.fetch(ctx, ds.url("/max-age.json"))
		require.NoError(t, err)
		assert.Equal(t, 1, ds.hitCount("/max-age.json"))

		*now = now.Add(2 * time.Second)
		_, err = f.fetch(ctx, ds.url("/max-age.json"))
		require.NoError(t, err)
		assert.Equal(t, 2, ds.hitCount("/max-age.json"))
	})

	t.Run("no-store documents are not cached", func(t *testing.T) {
		f, _ := newFetcher()
		for i := 0; i < 2; i++ {
			_, err := f.fetch(ctx, ds.url("/no-store.json"))
			require.NoError(t, err)
		}
		assert.Equal(t, 2, ds.hitCount("/no-store.json"))
	})

	t.Run("application/*+json content type is accepted", func(t *testing.T) {
		f, _ := newFetcher()
		_, err := f.fetch(ctx, ds.url("/plus-json.json"))
		require.NoError(t, err)
	})

	t.Run("errors are not cached", func(t *testing.T) {
		f, _ := newFetcher()

		_, err := f.fetch(ctx, ds.url("/flaky.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP status 500")

		_, err = f.fetch(ctx, ds.url("/flaky.json"))
		require.NoError(t, err)
		assert.Equal(t, 2, ds.hitCount("/flaky.json"))
	})

	t.Run("redirects are not followed", func(t *testing.T) {
		f, _ := newFetcher()
		before := ds.hitCount("/valid.json")

		_, err := f.fetch(ctx, ds.url("/redirect.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP status 302")
		assert.Equal(t, before, ds.hitCount("/valid.json"), "redirect target must not be requested")
	})

	invalid := map[string]string{
		"/mismatch.json":         "does not match the client_id URL",
		"/secret.json":           "must not contain client_secret",
		"/secret-auth.json":      "token_endpoint_auth_method must be 'none'",
		"/no-redirect-uris.json": "redirect_uris is required",
		"/bad-grant.json":        "grant_types must only contain",
		"/text.json":             "must be served as JSON",
		"/large.json":            "at most 5120 bytes",
		"/invalid-json.json":     "not valid JSON",
		"/missing.json":          "HTTP status 404",
	}
	for path, reason := range invalid {
		t.Run("rejects "+path, func(t *testing.T) {
			f, _ := newFetcher()

			for i := 0; i < 2; i++ {
				_, err := f.fetch(ctx, ds.url(path))
				require.Error(t, err)

				var metadataErr *clientMetadataError
				require.True(t, errors.As(err, &metadataErr), "expected *clientMetadataError, got %T", err)
				assert.Contains(t, metadataErr.Reason, reason)
			}
			assert.Equal(t, 2, ds.hitCount(path), "invalid documents must not be cached")
		})
	}
}

func TestClientMetadataFetcherRefusesSpecialUseAddresses(t *testing.T) {
	// The test server listens on 127.0.0.1, which the default client refuses
	ds := newDocumentServer(t, map[string]func(http.ResponseWriter, string){
		"/valid.json": jsonDocument(nil),
	})

	f := newClientMetadataFetcher(nil)
	_, err := f.fetch(context.Background(), ds.url("/valid.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "special-use address")
	assert.Equal(t, 0, ds.hitCount("/valid.json"))
}

// ---------- authorization endpoint ----------

func (ts *OAuthAuthorizeTestSuite) useDocumentServer(ds *documentServer) {
	previous := ts.Server.clientMetadata
	ts.Server.clientMetadata = newClientMetadataFetcher(ds.Client())
	ts.Config.OAuthServer.AllowClientIDMetadataDocuments = true

	ts.T().Cleanup(func() {
		ts.Server.clientMetadata = previous
		ts.Config.OAuthServer.AllowClientIDMetadataDocuments = false
		ts.Config.OAuthServer.ClientIDMetadataDocumentAllowedHosts = nil
	})
}

func (ts *OAuthAuthorizeTestSuite) authorizeWithClientID(clientID, redirectURI string) (*httptest.ResponseRecorder, error) {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	return w, ts.Server.OAuthServerAuthorize(w, req)
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_ClientIDMetadataDocumentCreatesSingleClient() {
	ds := newDocumentServer(ts.T(), map[string]func(http.ResponseWriter, string){
		"/client.json": jsonDocument(nil),
	})
	ts.useDocumentServer(ds)
	clientIDURL := ds.url("/client.json")

	var authIDs []string
	for i := 0; i < 2; i++ {
		w, err := ts.authorizeWithClientID(clientIDURL, testCIMDRedirectURI)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), http.StatusFound, w.Code, w.Body.String())

		loc, err := url.Parse(w.Header().Get("Location"))
		require.NoError(ts.T(), err)
		authID := loc.Query().Get("authorization_id")
		require.NotEmpty(ts.T(), authID, "unexpected error=%q", loc.Query().Get("error"))
		authIDs = append(authIDs, authID)
	}

	client, err := models.FindOAuthServerClientByClientIDURL(ts.DB, clientIDURL)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), models.OAuthServerRegistrationTypeMetadataDocument, client.RegistrationType)
	assert.True(ts.T(), client.IsPublic())
	assert.Equal(ts.T(), models.TokenEndpointAuthMethodNone, client.TokenEndpointAuthMethod)
	assert.Equal(ts.T(), "Test MCP Client", *client.ClientName)
	assert.Equal(ts.T(), []string{testCIMDRedirectURI}, client.GetRedirectURIs())
	assert.Equal(ts.T(), clientIDURL, client.Identifier())

	// Both authorizations belong to the same client: one app, one entry
	for _, authID := range authIDs {
		assert.Equal(ts.T(), client.ID, ts.reload(authID).ClientID)
	}
	count, err := ts.DB.Q().Where("client_id_url = ?", clientIDURL).Count(&models.OAuthServerClient{})
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), 1, count)

	// The consent screen gets the URL so it can show its host
	user := ts.createUser("cimd-details@example.com")
	w := httptest.NewRecorder()
	require.NoError(ts.T(), ts.Server.OAuthServerGetAuthorization(w, ts.newRequest(http.MethodGet, authIDs[0], user, nil)))
	var resp AuthorizationDetailsResponse
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(ts.T(), clientIDURL, resp.Client.ClientIDURL)
	assert.Equal(ts.T(), "Test MCP Client", resp.Client.Name)
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_ClientIDMetadataDocumentChangesAreApplied() {
	name := "First Name"
	ds := newDocumentServer(ts.T(), map[string]func(http.ResponseWriter, string){
		"/client.json": func(w http.ResponseWriter, clientID string) {
			jsonDocument(func(doc map[string]any) { doc["client_name"] = name }, "Cache-Control", "no-store")(w, clientID)
		},
	})
	ts.useDocumentServer(ds)
	clientIDURL := ds.url("/client.json")

	_, err := ts.authorizeWithClientID(clientIDURL, testCIMDRedirectURI)
	require.NoError(ts.T(), err)

	name = "Second Name"
	_, err = ts.authorizeWithClientID(clientIDURL, testCIMDRedirectURI)
	require.NoError(ts.T(), err)

	client, err := models.FindOAuthServerClientByClientIDURL(ts.DB, clientIDURL)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), "Second Name", *client.ClientName)
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_ClientIDMetadataDocumentRejected() {
	ds := newDocumentServer(ts.T(), map[string]func(http.ResponseWriter, string){
		"/client.json": jsonDocument(nil),
		"/secret.json": jsonDocument(func(doc map[string]any) { doc["client_secret"] = "s3cret" }),
	})
	ts.useDocumentServer(ds)

	// Invalid document: rejected without redirecting, and no client is created
	_, err := ts.authorizeWithClientID(ds.url("/secret.json"), testCIMDRedirectURI)
	ts.assertHTTPError(err, http.StatusBadRequest, apierrors.ErrorCodeValidationFailed)
	assert.Contains(ts.T(), err.(*apierrors.HTTPError).Message, "must not contain client_secret")
	_, err = models.FindOAuthServerClientByClientIDURL(ts.DB, ds.url("/secret.json"))
	assert.True(ts.T(), models.IsNotFoundError(err))

	// redirect_uri not listed in the document
	_, err = ts.authorizeWithClientID(ds.url("/client.json"), "https://attacker.example.com/callback")
	ts.assertHTTPError(err, http.StatusBadRequest, apierrors.ErrorCodeValidationFailed)
	assert.Contains(ts.T(), err.(*apierrors.HTTPError).Message, "invalid redirect_uri")

	// Host not in the allow list
	ts.Config.OAuthServer.ClientIDMetadataDocumentAllowedHosts = []string{"claude.ai"}
	_, err = ts.authorizeWithClientID(ds.url("/client.json"), testCIMDRedirectURI)
	ts.assertHTTPError(err, http.StatusBadRequest, apierrors.ErrorCodeValidationFailed)
	assert.Contains(ts.T(), err.(*apierrors.HTTPError).Message, "host is not allowed")
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_ClientIDMetadataDocumentDisabled() {
	ds := newDocumentServer(ts.T(), map[string]func(http.ResponseWriter, string){
		"/client.json": jsonDocument(nil),
	})
	ts.useDocumentServer(ds)
	ts.Config.OAuthServer.AllowClientIDMetadataDocuments = false

	_, err := ts.authorizeWithClientID(ds.url("/client.json"), testCIMDRedirectURI)
	ts.assertHTTPError(err, http.StatusBadRequest, apierrors.ErrorCodeOAuthClientNotFound)
	assert.Equal(ts.T(), 0, ds.hitCount("/client.json"), "document must not be fetched when disabled")
}

// ---------- token endpoint ----------

func (ts *OAuthClientTestSuite) createMetadataDocumentClient(clientIDURL string) *models.OAuthServerClient {
	client := &models.OAuthServerClient{
		ID:                      uuid.Must(uuid.NewV4()),
		RegistrationType:        models.OAuthServerRegistrationTypeMetadataDocument,
		ClientType:              models.OAuthServerClientTypePublic,
		TokenEndpointAuthMethod: models.TokenEndpointAuthMethodNone,
		ClientIDURL:             &clientIDURL,
	}
	client.SetRedirectURIs([]string{testCIMDRedirectURI})
	client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	require.NoError(ts.T(), models.CreateOAuthServerClient(ts.DB, client))
	return client
}

func (ts *OAuthClientTestSuite) TestFindClientByClientID() {
	ts.Config.OAuthServer.AllowClientIDMetadataDocuments = true
	ts.T().Cleanup(func() { ts.Config.OAuthServer.AllowClientIDMetadataDocuments = false })

	registered, _ := ts.createTestOAuthClient()
	clientIDURL := "https://mcp-client.example.com/client.json"
	metadataClient := ts.createMetadataDocumentClient(clientIDURL)

	found, err := FindClientByClientID(ts.DB, &ts.Config.OAuthServer, registered.ID.String())
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), registered.ID, found.ID)

	found, err = FindClientByClientID(ts.DB, &ts.Config.OAuthServer, clientIDURL)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), metadataClient.ID, found.ID)

	_, err = FindClientByClientID(ts.DB, &ts.Config.OAuthServer, "https://unknown.example.com/client.json")
	assert.True(ts.T(), models.IsNotFoundError(err))

	_, err = FindClientByClientID(ts.DB, &ts.Config.OAuthServer, "not-a-client-id")
	assert.ErrorIs(ts.T(), err, ErrInvalidClientIDFormat)

	// Deleted clients can't be used
	require.NoError(ts.T(), ts.Server.deleteOAuthServerClient(context.Background(), metadataClient.ID))
	_, err = FindClientByClientID(ts.DB, &ts.Config.OAuthServer, clientIDURL)
	assert.True(ts.T(), models.IsNotFoundError(err))

	// URL client_ids are rejected when the feature is disabled
	ts.Config.OAuthServer.AllowClientIDMetadataDocuments = false
	_, err = FindClientByClientID(ts.DB, &ts.Config.OAuthServer, clientIDURL)
	assert.ErrorIs(ts.T(), err, ErrInvalidClientIDFormat)
}

func (ts *OAuthClientTestSuite) cimdTokenRequest(client *models.OAuthServerClient, form url.Values) map[string]interface{} {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
	w := httptest.NewRecorder()

	require.NoError(ts.T(), ts.Server.OAuthToken(w, req))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	var resp map[string]interface{}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

func cimdAccessTokenClientID(t *testing.T, resp map[string]interface{}) string {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(resp["access_token"].(string), claims)
	require.NoError(t, err)
	clientID, _ := claims["client_id"].(string)
	return clientID
}

func (ts *OAuthClientTestSuite) TestClientIDMetadataDocument_TokensUseClientIDURL() {
	ts.Config.OAuthServer.AllowClientIDMetadataDocuments = true
	ts.T().Cleanup(func() { ts.Config.OAuthServer.AllowClientIDMetadataDocuments = false })

	clientIDURL := "https://mcp-client.example.com/client.json"
	ts.createMetadataDocumentClient(clientIDURL)

	// Token requests identify the client by its URL, as the middleware does
	client, err := FindClientByClientID(ts.DB, &ts.Config.OAuthServer, clientIDURL)
	require.NoError(ts.T(), err)

	user := ts.createTestUser("cimd-token@example.com")
	code := ts.mintApprovedCode(client.ID, user.ID)

	resp := ts.cimdTokenRequest(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
	})
	assert.Equal(ts.T(), clientIDURL, cimdAccessTokenClientID(ts.T(), resp))

	resp = ts.cimdTokenRequest(client, url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {resp["refresh_token"].(string)},
	})
	assert.Equal(ts.T(), clientIDURL, cimdAccessTokenClientID(ts.T(), resp))
}

func (ts *OAuthClientTestSuite) TestRegisteredClientTokensKeepUUIDClientID() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("uuid-token@example.com")
	code := ts.mintApprovedCode(client.ID, user.ID)

	resp := ts.cimdTokenRequest(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
	})
	assert.Equal(ts.T(), client.ID.String(), cimdAccessTokenClientID(ts.T(), resp))
}
