package api

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type SCIMTokensTestSuite struct {
	suite.Suite
	API      *API
	Config   *conf.GlobalConfiguration
	AdminJWT string
	Provider *models.SSOProvider
}

func TestSCIMTokens(t *testing.T) {
	api, config := setupSCIMAPI(t, nil)
	defer func() { require.NoError(t, api.db.Close()) }()

	suite.Run(t, &SCIMTokensTestSuite{API: api, Config: config})
}

func (ts *SCIMTokensTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))
	ts.API.config.SSO.SCIM.Enabled = true

	ts.AdminJWT = adminJWT(ts.T(), ts.Config.JWT.Secret)

	ts.Provider = ts.createProvider()
}

func (ts *SCIMTokensTestSuite) TestCreate() {
	w := ts.request(http.MethodPost, ts.tokensPath(ts.Provider), map[string]any{})
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())

	var body map[string]any
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &body))
	require.ElementsMatch(ts.T(), []string{"base_url", "token", "prefix", "created_at", "expires_at", "revoked_at", "last_used_at"}, slices.Collect(maps.Keys(body)))
	require.Equal(ts.T(), "http://localhost:9999/scim/v2", body["base_url"])
	require.Regexp(ts.T(), `^scim_[0-9a-f]{40}$`, body["token"])
	require.Equal(ts.T(), body["token"].(string)[:12], body["prefix"])
	require.Nil(ts.T(), body["expires_at"])
	require.Nil(ts.T(), body["revoked_at"])

	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(body["token"].(string)).Code)
}

func (ts *SCIMTokensTestSuite) TestMultipleActiveTokens() {
	first := ts.create(ts.Provider, map[string]any{})
	second := ts.create(ts.Provider, map[string]any{})

	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(first.Token).Code)
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(second.Token).Code)
}

func (ts *SCIMTokensTestSuite) TestCreateWithoutBody() {
	r := httptest.NewRequest(http.MethodPost, ts.tokensPath(ts.Provider), nil)
	r.Header.Set("Authorization", "Bearer "+ts.AdminJWT)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, r)

	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
}

func (ts *SCIMTokensTestSuite) TestCreateWithExpiry() {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	response := ts.create(ts.Provider, map[string]any{"expires_at": expiresAt})

	require.NotNil(ts.T(), response.ExpiresAt)
	require.True(ts.T(), expiresAt.Equal(*response.ExpiresAt))
}

func (ts *SCIMTokensTestSuite) TestCreateRejectsPastExpiry() {
	w := ts.request(http.MethodPost, ts.tokensPath(ts.Provider), map[string]any{"expires_at": time.Now().Add(-time.Minute)})

	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), "validation_failed")
}

func (ts *SCIMTokensTestSuite) TestCreateRejectsExpiryBeforeDatabaseClock() {
	expiresAt := time.Now().Add(-time.Minute)
	ts.API.overrideTime = func() time.Time { return expiresAt.Add(-time.Hour) }
	defer func() { ts.API.overrideTime = nil }()

	w := ts.request(http.MethodPost, ts.tokensPath(ts.Provider), map[string]any{"expires_at": expiresAt})

	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), "validation_failed")
}

func (ts *SCIMTokensTestSuite) TestCreateRejectsOversizedBody() {
	w := ts.request(http.MethodPost, ts.tokensPath(ts.Provider), strings.Repeat("a", 1<<20))

	require.Equal(ts.T(), http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), "request_entity_too_large")
}

func (ts *SCIMTokensTestSuite) TestCreateForUnknownProvider() {
	w := ts.request(http.MethodPost, "/admin/sso/providers/"+uuid.Must(uuid.NewV4()).String()+"/scim/tokens", map[string]any{})

	require.Equal(ts.T(), http.StatusNotFound, w.Code)
	require.Contains(ts.T(), w.Body.String(), "sso_provider_not_found")
}

func (ts *SCIMTokensTestSuite) TestList() {
	first := ts.create(ts.Provider, map[string]any{})
	second := ts.create(ts.Provider, map[string]any{})
	ts.create(ts.createProvider(), map[string]any{})
	require.Equal(ts.T(), http.StatusOK, ts.request(http.MethodDelete, ts.tokensPath(ts.Provider)+"/"+second.Prefix, nil).Code)

	w := ts.request(http.MethodGet, ts.tokensPath(ts.Provider), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.NotContains(ts.T(), w.Body.String(), first.Token)
	require.NotContains(ts.T(), w.Body.String(), second.Token)

	var body struct {
		Tokens []map[string]any `json:"tokens"`
	}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(ts.T(), body.Tokens, 2)
	require.ElementsMatch(ts.T(), []string{"prefix", "created_at", "expires_at", "revoked_at", "last_used_at"}, slices.Collect(maps.Keys(body.Tokens[0])))
	require.ElementsMatch(ts.T(), []any{first.Prefix, second.Prefix}, []any{body.Tokens[0]["prefix"], body.Tokens[1]["prefix"]})
}

func (ts *SCIMTokensTestSuite) TestListEmpty() {
	w := ts.request(http.MethodGet, ts.tokensPath(ts.Provider), nil)

	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.JSONEq(ts.T(), `{"tokens":[]}`, w.Body.String())
}

func (ts *SCIMTokensTestSuite) TestRevoke() {
	created := ts.create(ts.Provider, map[string]any{})
	path := ts.tokensPath(ts.Provider) + "/" + created.Prefix

	w := ts.request(http.MethodDelete, path, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	var revoked models.SCIMToken
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &revoked))
	require.Equal(ts.T(), created.Prefix, revoked.Prefix)
	require.NotNil(ts.T(), revoked.RevokedAt)

	require.Equal(ts.T(), http.StatusUnauthorized, ts.scimRequest(created.Token).Code)

	w = ts.request(http.MethodDelete, path, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	var again models.SCIMToken
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &again))
	require.True(ts.T(), revoked.RevokedAt.Equal(*again.RevokedAt))
}

func (ts *SCIMTokensTestSuite) TestRevokeUnknownPrefix() {
	created := ts.create(ts.createProvider(), map[string]any{})

	for _, prefix := range []string{"scim_0000000", created.Prefix} {
		w := ts.request(http.MethodDelete, ts.tokensPath(ts.Provider)+"/"+prefix, nil)

		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		require.Contains(ts.T(), w.Body.String(), "scim_token_not_found")
	}
}

func (ts *SCIMTokensTestSuite) TestRequiresAdmin() {
	created := ts.create(ts.Provider, nil)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/admin/sso/providers/" + ts.Provider.ID.String() + "/scim"},
		{http.MethodPost, "/admin/sso/providers/" + ts.Provider.ID.String() + "/scim"},
		{http.MethodDelete, "/admin/sso/providers/" + ts.Provider.ID.String() + "/scim"},
		{http.MethodGet, ts.tokensPath(ts.Provider)},
		{http.MethodPost, ts.tokensPath(ts.Provider)},
		{http.MethodDelete, ts.tokensPath(ts.Provider) + "/" + created.Prefix},
	} {
		r := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()

		ts.API.handler.ServeHTTP(w, r)

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code, route.method+" "+route.path)
	}
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(created.Token).Code)
}

func (ts *SCIMTokensTestSuite) TestSCIMRejectsAdminCredentials() {
	for _, role := range []string{"service_role", "supabase_admin"} {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: role}).SignedString([]byte(ts.Config.JWT.Secret))
		require.NoError(ts.T(), err)

		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, r)

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code, role)
	}
}

func (ts *SCIMTokensTestSuite) TestDisabled() {
	ts.API.config.SSO.SCIM.Enabled = false

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, ts.tokensPath(ts.Provider)},
		{http.MethodPost, ts.tokensPath(ts.Provider)},
		{http.MethodGet, ts.scimPath(ts.Provider)},
		{http.MethodPost, ts.scimPath(ts.Provider)},
		{http.MethodDelete, ts.scimPath(ts.Provider)},
	} {
		w := ts.request(tc.method, tc.path, map[string]any{})

		require.Equal(ts.T(), http.StatusNotFound, w.Code, tc.method+" "+tc.path)
		require.Contains(ts.T(), w.Body.String(), "feature_disabled")
	}
}

func (ts *SCIMTokensTestSuite) TestStatus() {
	status := ts.status(http.MethodGet, createSSOProvider(ts.T(), ts.API.db))
	require.False(ts.T(), status.Enabled)
	require.Equal(ts.T(), ts.baseURL(), status.BaseURL)
	require.Empty(ts.T(), status.Tokens)

	status = ts.status(http.MethodGet, ts.Provider)
	require.True(ts.T(), status.Enabled)
	require.Equal(ts.T(), ts.baseURL(), status.BaseURL)
	require.Empty(ts.T(), status.Tokens)

	active := ts.create(ts.Provider, map[string]any{})
	revoked := ts.create(ts.Provider, map[string]any{})
	w := ts.request(http.MethodDelete, ts.tokensPath(ts.Provider)+"/"+revoked.Prefix, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	ts.create(ts.createProvider(), map[string]any{})

	w = ts.request(http.MethodGet, ts.scimPath(ts.Provider), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), w.Body.String(), active.Token)
	require.NotContains(ts.T(), w.Body.String(), "token_hash")

	status = ts.status(http.MethodGet, ts.Provider)
	require.True(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 1)
	require.Equal(ts.T(), active.Prefix, status.Tokens[0].Prefix)
}

func (ts *SCIMTokensTestSuite) TestEnableWithZeroTokens() {
	provider := createSSOProvider(ts.T(), ts.API.db)

	status := ts.status(http.MethodPost, provider)
	require.True(ts.T(), status.Enabled)
	require.Equal(ts.T(), ts.baseURL(), status.BaseURL)
	require.Empty(ts.T(), status.Tokens)
	require.True(ts.T(), ts.status(http.MethodGet, provider).Enabled)
}

func (ts *SCIMTokensTestSuite) TestEnableAndDisableLeaveTokensUnchanged() {
	ts.create(ts.Provider, map[string]any{})
	expiring := ts.create(ts.Provider, map[string]any{"expires_at": time.Now().Add(time.Hour)})
	ts.revoke(ts.create(ts.Provider, map[string]any{}).Prefix)
	before, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.Provider.ID)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), expiring.ExpiresAt)

	for _, method := range []string{http.MethodDelete, http.MethodDelete, http.MethodPost, http.MethodPost} {
		ts.status(method, ts.Provider)
		after, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.Provider.ID)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), before, after, method)
	}
}

func (ts *SCIMTokensTestSuite) TestDisableStopsAuthenticatedRequests() {
	token := ts.create(ts.Provider, map[string]any{})

	status := ts.status(http.MethodDelete, ts.Provider)
	require.False(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 1)

	for _, path := range []string{"/scim/v2/Users", "/scim/v2/Groups", "/scim/v2/Schemas", "/scim/v2/ResourceTypes", "/scim/v2/ServiceProviderConfig"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token.Token)
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, r)

		expected := http.StatusUnauthorized
		if path == "/scim/v2/ServiceProviderConfig" {
			expected = http.StatusOK
		}
		require.Equal(ts.T(), expected, w.Code, path)
	}
}

func (ts *SCIMTokensTestSuite) TestReenableRestoresExistingTokens() {
	token := ts.create(ts.Provider, map[string]any{})
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(token.Token).Code)

	ts.status(http.MethodDelete, ts.Provider)
	require.Equal(ts.T(), http.StatusUnauthorized, ts.scimRequest(token.Token).Code)

	status := ts.status(http.MethodPost, ts.Provider)
	require.True(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 1)
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(token.Token).Code)

	require.Equal(ts.T(), []scimTokenEvent{
		{string(models.SCIMTokenCreatedAction), token.Prefix},
		{string(models.SCIMDisabledAction), ""},
		{string(models.SCIMEnabledAction), ""},
	}, ts.tokenEvents())
}

func (ts *SCIMTokensTestSuite) TestMintAndRevokeWhileDisabled() {
	ts.status(http.MethodDelete, ts.Provider)

	token := ts.create(ts.Provider, map[string]any{})
	require.Equal(ts.T(), http.StatusUnauthorized, ts.scimRequest(token.Token).Code)
	revoked := ts.create(ts.Provider, map[string]any{})
	ts.revoke(revoked.Prefix)

	ts.status(http.MethodPost, ts.Provider)
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(token.Token).Code)
	require.Equal(ts.T(), http.StatusUnauthorized, ts.scimRequest(revoked.Token).Code)

	require.Equal(ts.T(), []scimTokenEvent{
		{string(models.SCIMDisabledAction), ""},
		{string(models.SCIMTokenCreatedAction), token.Prefix},
		{string(models.SCIMTokenCreatedAction), revoked.Prefix},
		{string(models.SCIMTokenRevokedAction), revoked.Prefix},
		{string(models.SCIMEnabledAction), ""},
	}, ts.tokenEvents())
}

func (ts *SCIMTokensTestSuite) TestStatusIndependentOfTokens() {
	require.True(ts.T(), ts.status(http.MethodGet, ts.Provider).Enabled)

	token := ts.create(ts.Provider, map[string]any{})
	ts.revoke(token.Prefix)
	require.True(ts.T(), ts.status(http.MethodGet, ts.Provider).Enabled)

	ts.create(ts.Provider, map[string]any{})
	ts.status(http.MethodDelete, ts.Provider)
	status := ts.status(http.MethodGet, ts.Provider)
	require.False(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 1)
}

func (ts *SCIMTokensTestSuite) TestConcurrentEnableAndDisable() {
	provider := createSSOProvider(ts.T(), ts.API.db)

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		var wg sync.WaitGroup
		codes := make(chan int, 10)
		for range 10 {
			wg.Go(func() {
				codes <- ts.request(method, ts.scimPath(provider), nil).Code
			})
		}
		wg.Wait()
		close(codes)
		for code := range codes {
			require.Equal(ts.T(), http.StatusOK, code, method)
		}
	}

	require.Equal(ts.T(), []string{string(models.SCIMEnabledAction), string(models.SCIMDisabledAction)}, ts.scimActions(provider))
}

func (ts *SCIMTokensTestSuite) TestStatusForUnknownProvider() {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		w := ts.request(method, "/admin/sso/providers/"+uuid.Must(uuid.NewV4()).String()+"/scim", nil)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, method)
		require.Contains(ts.T(), w.Body.String(), "sso_provider_not_found", method)
	}
	require.Empty(ts.T(), ts.tokenEvents())
}

func (ts *SCIMTokensTestSuite) TestStatusForDisabledProvider() {
	first := ts.create(ts.Provider, map[string]any{})
	ts.setProviderDisabled(true)

	status := ts.status(http.MethodGet, ts.Provider)
	require.False(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 1)
	require.Equal(ts.T(), http.StatusUnauthorized, ts.scimRequest(first.Token).Code)

	second := ts.create(ts.Provider, map[string]any{})
	third := ts.create(ts.Provider, map[string]any{})
	status = ts.status(http.MethodGet, ts.Provider)
	require.False(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 3)

	ts.revoke(first.Prefix)
	ts.setProviderDisabled(false)
	status = ts.status(http.MethodGet, ts.Provider)
	require.True(ts.T(), status.Enabled)
	require.Len(ts.T(), status.Tokens, 2)
	require.Equal(ts.T(), http.StatusOK, ts.scimRequest(second.Token).Code)

	ts.setProviderDisabled(true)
	ts.revoke(third.Prefix)

	require.Equal(ts.T(), []scimTokenEvent{
		{string(models.SCIMTokenCreatedAction), first.Prefix},
		{string(models.SCIMTokenCreatedAction), second.Prefix},
		{string(models.SCIMTokenCreatedAction), third.Prefix},
		{string(models.SCIMTokenRevokedAction), first.Prefix},
		{string(models.SCIMTokenRevokedAction), third.Prefix},
	}, ts.tokenEvents())
}

type scimTokenEvent struct{ action, prefix string }

func (ts *SCIMTokensTestSuite) TestAuditLog() {
	first := ts.create(ts.Provider, map[string]any{})
	second := ts.create(ts.Provider, map[string]any{})
	ts.revoke(first.Prefix)
	ts.revoke(first.Prefix)
	ts.revoke(second.Prefix)
	ts.status(http.MethodDelete, ts.Provider)
	ts.status(http.MethodDelete, ts.Provider)
	ts.status(http.MethodPost, ts.Provider)
	ts.status(http.MethodPost, ts.Provider)

	w := ts.request(http.MethodPost, ts.tokensPath(ts.Provider), map[string]any{"expires_at": "2000-01-01T00:00:00Z"})
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	ts.API.config.SSO.SCIM.Enabled = false
	w = ts.request(http.MethodDelete, ts.scimPath(ts.Provider), nil)
	require.Equal(ts.T(), http.StatusNotFound, w.Code, w.Body.String())
	ts.API.config.SSO.SCIM.Enabled = true

	require.Equal(ts.T(), []scimTokenEvent{
		{string(models.SCIMTokenCreatedAction), first.Prefix},
		{string(models.SCIMTokenCreatedAction), second.Prefix},
		{string(models.SCIMTokenRevokedAction), first.Prefix},
		{string(models.SCIMTokenRevokedAction), second.Prefix},
		{string(models.SCIMDisabledAction), ""},
		{string(models.SCIMEnabledAction), ""},
	}, ts.tokenEvents())
}

func (ts *SCIMTokensTestSuite) TestDisableNeverEnabledWritesNoEvent() {
	provider := createSSOProvider(ts.T(), ts.API.db)

	status := ts.status(http.MethodDelete, provider)
	require.False(ts.T(), status.Enabled)
	require.Empty(ts.T(), ts.scimActions(provider))
}

func (ts *SCIMTokensTestSuite) TestEnableSSODisabledProvider() {
	provider := createSSOProvider(ts.T(), ts.API.db)
	require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE "+provider.TableName()+" SET disabled = true WHERE id = ?", provider.ID).Exec())

	require.False(ts.T(), ts.status(http.MethodPost, provider).Enabled)
	require.Equal(ts.T(), []string{string(models.SCIMEnabledAction)}, ts.scimActions(provider))

	require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE "+provider.TableName()+" SET disabled = false WHERE id = ?", provider.ID).Exec())
	require.True(ts.T(), ts.status(http.MethodGet, provider).Enabled)
}

func (ts *SCIMTokensTestSuite) createProvider() *models.SSOProvider {
	return createSCIMEnabledProvider(ts.T(), ts.API.db)
}

func (ts *SCIMTokensTestSuite) tokensPath(provider *models.SSOProvider) string {
	return "/admin/sso/providers/" + provider.ID.String() + "/scim/tokens"
}

func (ts *SCIMTokensTestSuite) baseURL() string {
	return strings.TrimRight(ts.API.config.API.ExternalURL, "/") + "/scim/v2"
}

func (ts *SCIMTokensTestSuite) request(method, path string, body any) *httptest.ResponseRecorder {
	return serveAdmin(ts.T(), ts.API, method, path, body)
}

func (ts *SCIMTokensTestSuite) create(provider *models.SSOProvider, body any) AdminSCIMTokenCreateResponse {
	w := ts.request(http.MethodPost, ts.tokensPath(provider), body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())

	var response AdminSCIMTokenCreateResponse
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &response))
	return response
}

func (ts *SCIMTokensTestSuite) scimRequest(token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
}

func (ts *SCIMTokensTestSuite) scimPath(provider *models.SSOProvider) string {
	return "/admin/sso/providers/" + provider.ID.String() + "/scim"
}

func (ts *SCIMTokensTestSuite) status(method string, provider *models.SSOProvider) AdminSCIMStatusResponse {
	w := ts.request(method, ts.scimPath(provider), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	var response AdminSCIMStatusResponse
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &response))
	return response
}

func (ts *SCIMTokensTestSuite) scimActions(provider *models.SSOProvider) []string {
	entries := queryAuditEntries(ts.T(), ts.API.db, "payload->>'log_type' = ? AND payload->'traits'->>'sso_provider_id' = ?", "scim", provider.ID.String())
	actions := []string{}
	for _, entry := range entries {
		actions = append(actions, entry.Payload["action"].(string))
	}
	return actions
}

func (ts *SCIMTokensTestSuite) setProviderDisabled(disabled bool) {
	require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE "+ts.Provider.TableName()+" SET disabled = ? WHERE id = ?", disabled, ts.Provider.ID).Exec())
}

func (ts *SCIMTokensTestSuite) tokenEvents() []scimTokenEvent {
	entries := queryAuditEntries(ts.T(), ts.API.db, "payload->>'log_type' = ?", "scim")

	events := []scimTokenEvent{}
	for _, entry := range entries {
		require.Equal(ts.T(), "supabase_admin", entry.Payload["actor_username"])
		traits := entry.Payload["traits"].(map[string]any)
		require.Equal(ts.T(), ts.Provider.ID.String(), traits["sso_provider_id"])
		require.Equal(ts.T(), "success", traits["outcome"])
		prefix, _ := traits["token_prefix"].(string)
		if prefixes, ok := traits["token_prefixes"].([]any); ok && len(prefixes) > 0 {
			require.Len(ts.T(), prefixes, 1)
			prefix = prefixes[0].(string)
		}
		events = append(events, scimTokenEvent{entry.Payload["action"].(string), prefix})
	}
	return events
}

func (ts *SCIMTokensTestSuite) revoke(prefix string) {
	w := ts.request(http.MethodDelete, ts.tokensPath(ts.Provider)+"/"+prefix, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}
