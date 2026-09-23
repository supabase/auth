package api

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type SCIMTokensTestSuite struct {
	suite.Suite
	API      *API
	Config   *conf.GlobalConfiguration
	AdminJWT string
	Provider *models.SSOProvider
}

func TestSCIMTokens(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.Experimental.ScimEnabled = true
		}
	})
	require.NoError(t, err)
	defer api.db.Close()

	suite.Run(t, &SCIMTokensTestSuite{API: api, Config: config})
}

func (ts *SCIMTokensTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))
	ts.API.config.Experimental.ScimEnabled = true

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	ts.AdminJWT = token

	ts.Provider = ts.createProvider()
}

func (ts *SCIMTokensTestSuite) createProvider() *models.SSOProvider {
	provider := &models.SSOProvider{}
	require.NoError(ts.T(), ts.API.db.Create(provider))
	return provider
}

func (ts *SCIMTokensTestSuite) tokensPath(provider *models.SSOProvider) string {
	return "/admin/sso/providers/" + provider.ID.String() + "/scim/tokens"
}

func (ts *SCIMTokensTestSuite) request(method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		require.NoError(ts.T(), json.NewEncoder(&buf).Encode(body))
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Authorization", "Bearer "+ts.AdminJWT)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
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

func (ts *SCIMTokensTestSuite) TestCreateWithoutBody() {
	r := httptest.NewRequest(http.MethodPost, ts.tokensPath(ts.Provider), nil)
	r.Header.Set("Authorization", "Bearer "+ts.AdminJWT)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, r)

	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
}

func (ts *SCIMTokensTestSuite) TestTokenValidatorResolvesSSOProvider() {
	created := ts.create(ts.Provider, map[string]any{})
	validate := scim.NewTokenValidator(ts.API.db)

	ctx, err := validate(context.Background(), created.Token)
	require.NoError(ts.T(), err)
	providerID, ok := scim.SSOProviderID(ctx)
	require.True(ts.T(), ok)
	require.Equal(ts.T(), ts.Provider.ID, providerID)

	ctx, err = validate(context.Background(), "scim_invalid")
	require.Error(ts.T(), err)
	_, ok = scim.SSOProviderID(ctx)
	require.False(ts.T(), ok)
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
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, ts.tokensPath(ts.Provider), nil)
		w := httptest.NewRecorder()

		ts.API.handler.ServeHTTP(w, r)

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
	}
}

func (ts *SCIMTokensTestSuite) TestDisabled() {
	ts.API.config.Experimental.ScimEnabled = false

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		w := ts.request(method, ts.tokensPath(ts.Provider), map[string]any{})

		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		require.Contains(ts.T(), w.Body.String(), "feature_disabled")
	}
}
