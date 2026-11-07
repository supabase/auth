package oauthserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

const testResource = "https://mcp.example.com/mcp"

// ---------- token endpoint (RFC 8707 section 2.2) ----------

func (ts *OAuthClientTestSuite) mintApprovedCodeWithResource(clientID, userID uuid.UUID, resource string) string {
	auth := models.NewOAuthServerAuthorization(models.NewOAuthServerAuthorizationParams{
		ClientID:    clientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "profile",
		Resource:    resource,
		TTL:         time.Hour,
	})
	require.NoError(ts.T(), models.CreateOAuthServerAuthorization(ts.DB, auth))
	require.NoError(ts.T(), auth.SetUser(ts.DB, userID))
	require.NoError(ts.T(), auth.Approve(ts.DB))
	return *auth.AuthorizationCode
}

// postTokenForm calls the token endpoint with a form-encoded body, as OAuth clients do
func (ts *OAuthClientTestSuite) postTokenForm(client *models.OAuthServerClient, form url.Values) (map[string]interface{}, error) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
	w := httptest.NewRecorder()

	if err := ts.Server.OAuthToken(w, req); err != nil {
		return nil, err
	}
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	var resp map[string]interface{}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	return resp, nil
}

func (ts *OAuthClientTestSuite) accessTokenClaims(resp map[string]interface{}) jwt.MapClaims {
	accessToken, ok := resp["access_token"].(string)
	require.True(ts.T(), ok, "response is missing access_token")

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(accessToken, claims)
	require.NoError(ts.T(), err)
	return claims
}

func (ts *OAuthClientTestSuite) accessTokenAudience(resp map[string]interface{}) []string {
	aud, err := ts.accessTokenClaims(resp).GetAudience()
	require.NoError(ts.T(), err)
	return aud
}

func (ts *OAuthClientTestSuite) assertOAuthError(err error, code string) {
	ts.T().Helper()
	oauthErr, ok := err.(*apierrors.OAuthError)
	require.True(ts.T(), ok, "expected *apierrors.OAuthError, got %T (%v)", err, err)
	assert.Equal(ts.T(), code, oauthErr.Err)
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_CodeGrantBindsAudience() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-code@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, testResource)

	resp, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
		"resource":   {testResource},
	})
	require.NoError(ts.T(), err)

	// The user's audience stays first so the API keeps reading it from aud[0]
	assert.Equal(ts.T(), []string{"authenticated", testResource}, ts.accessTokenAudience(resp))

	sessionID, ok := ts.accessTokenClaims(resp)["session_id"].(string)
	require.True(ts.T(), ok)
	session, err := models.FindSessionByID(ts.DB, uuid.Must(uuid.FromString(sessionID)), false)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), session.Resource)
	assert.Equal(ts.T(), testResource, *session.Resource)
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_CodeGrantWithoutResourceParamUsesAuthorizedResource() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-code-implicit@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, testResource)

	resp, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
	})
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), []string{"authenticated", testResource}, ts.accessTokenAudience(resp))
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_NoResourceKeepsDefaultAudience() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-none@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, "")

	resp, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
	})
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), []string{"authenticated"}, ts.accessTokenAudience(resp))
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_CodeGrantRejectsMismatchedResource() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-mismatch@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, testResource)

	// Form-encoded requests must be checked too, not only JSON ones
	_, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
		"resource":   {"https://other.example.com/mcp"},
	})
	ts.assertOAuthError(err, "invalid_target")

	// A rejected request must not consume the code
	_, err = models.FindOAuthServerAuthorizationByCode(ts.DB, code)
	require.NoError(ts.T(), err)
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_CodeGrantRejectsResourceNotAuthorized() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-not-authorized@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, "")

	_, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
		"resource":   {testResource},
	})
	ts.assertOAuthError(err, "invalid_target")
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_TokenRejectsMultipleResources() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-multiple@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, testResource)

	_, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
		"resource":   {testResource, "https://other.example.com/mcp"},
	})
	ts.assertOAuthError(err, "invalid_target")
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_RefreshKeepsAudience() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("resource-refresh@example.com")
	code := ts.mintApprovedCodeWithResource(client.ID, user.ID, testResource)

	resp, err := ts.postTokenForm(client, url.Values{
		"grant_type": {GrantTypeAuthorizationCode},
		"code":       {code},
	})
	require.NoError(ts.T(), err)

	// Refresh without a resource parameter
	resp, err = ts.postTokenForm(client, url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {resp["refresh_token"].(string)},
	})
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), []string{"authenticated", testResource}, ts.accessTokenAudience(resp))

	// Refresh asking again for the granted resource
	resp, err = ts.postTokenForm(client, url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {resp["refresh_token"].(string)},
		"resource":      {testResource},
	})
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), []string{"authenticated", testResource}, ts.accessTokenAudience(resp))
}

func (ts *OAuthClientTestSuite) TestResourceIndicator_RefreshRejectsResourceNotGranted() {
	cases := []struct {
		name            string
		grantedResource string
	}{
		{name: "different resource", grantedResource: testResource},
		{name: "session without resource", grantedResource: ""},
	}

	for i, c := range cases {
		ts.Run(c.name, func() {
			client, _ := ts.createTestOAuthClient()
			user := ts.createTestUser(fmt.Sprintf("resource-refresh-reject-%d@example.com", i))
			code := ts.mintApprovedCodeWithResource(client.ID, user.ID, c.grantedResource)

			resp, err := ts.postTokenForm(client, url.Values{
				"grant_type": {GrantTypeAuthorizationCode},
				"code":       {code},
			})
			require.NoError(ts.T(), err)

			_, err = ts.postTokenForm(client, url.Values{
				"grant_type":    {GrantTypeRefreshToken},
				"refresh_token": {resp["refresh_token"].(string)},
				"resource":      {"https://other.example.com/mcp"},
			})
			ts.assertOAuthError(err, "invalid_target")
		})
	}
}

// ---------- authorization endpoint (RFC 8707 section 2) ----------

func (ts *OAuthAuthorizeTestSuite) authorizeQuery(clientID uuid.UUID) url.Values {
	return url.Values{
		"client_id":             {clientID.String()},
		"redirect_uri":          {"https://example.com/callback"},
		"scope":                 {"openid"},
		"state":                 {"xyz"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
		"code_challenge_method": {"S256"},
	}
}

func (ts *OAuthAuthorizeTestSuite) authorize(q url.Values) *url.URL {
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	require.NoError(ts.T(), ts.Server.OAuthServerAuthorize(w, req))
	require.Equal(ts.T(), http.StatusFound, w.Code, w.Body.String())

	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(ts.T(), err)
	return loc
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_ResourceIsStoredAndShownInDetails() {
	user := ts.createUser("authorize-resource@example.com")
	client := ts.createClient()

	q := ts.authorizeQuery(client.ID)
	q.Set("resource", testResource)
	loc := ts.authorize(q)

	authID := loc.Query().Get("authorization_id")
	require.NotEmpty(ts.T(), authID, "unexpected error=%q", loc.Query().Get("error"))
	auth := ts.reload(authID)
	require.NotNil(ts.T(), auth.Resource)
	assert.Equal(ts.T(), testResource, *auth.Resource)

	// The consent screen can show which resource the client asked for
	w := httptest.NewRecorder()
	require.NoError(ts.T(), ts.Server.OAuthServerGetAuthorization(w, ts.newRequest(http.MethodGet, authID, user, nil)))
	var resp AuthorizationDetailsResponse
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(ts.T(), testResource, resp.Resource)
}

func (ts *OAuthAuthorizeTestSuite) TestAuthorize_InvalidResourceRedirectsWithInvalidTarget() {
	client := ts.createClient()

	cases := []struct {
		name      string
		resources []string
	}{
		{name: "relative URI", resources: []string{"/mcp"}},
		{name: "fragment", resources: []string{testResource + "#section"}},
		{name: "query", resources: []string{testResource + "?tenant=a"}},
		{name: "too long", resources: []string{"https://mcp.example.com/" + strings.Repeat("a", maxResourceLength)}},
		{name: "multiple resources", resources: []string{testResource, "https://other.example.com/mcp"}},
	}

	for _, c := range cases {
		ts.Run(c.name, func() {
			q := ts.authorizeQuery(client.ID)
			q["resource"] = c.resources
			loc := ts.authorize(q)

			assert.Equal(ts.T(), "https://example.com/callback", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(ts.T(), "invalid_target", loc.Query().Get("error"))
			assert.Equal(ts.T(), "xyz", loc.Query().Get("state"))
			assert.Empty(ts.T(), loc.Query().Get("authorization_id"))
		})
	}
}
