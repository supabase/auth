package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type tenant struct {
	handler  http.Handler
	provider *models.SSOProvider
	users    []*core.User
	domain   string
	token    string
}

func (t *tenant) get(id string) *httptest.ResponseRecorder {
	return t.do("/scim/v2/Users/" + id)
}

func (t *tenant) list(query string) *httptest.ResponseRecorder {
	if query != "" {
		query = "?" + query
	}
	return t.do("/scim/v2/Users" + query)
}

func (t *tenant) do(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+t.token)
	r.Header.Set(scim.ProviderHeaderName, t.provider.ID.String())
	t.handler.ServeHTTP(w, r)
	return w
}

func (t *tenant) userIDs() []string {
	ids := make([]string, 0, len(t.users))
	for _, user := range t.users {
		ids = append(ids, user.ID)
	}
	return ids
}

type SCIMUsersTestSuite struct {
	suite.Suite
	API     *API
	Config  *conf.GlobalConfiguration
	Users   *scim.MemoryRepository[*core.User]
	TenantA *tenant
	TenantB *tenant
}

func TestSCIMUsers(t *testing.T) {
	users := scim.NewUserRepository()
	api, config, err := setupAPIForTestWithCallback(func(cfg *conf.GlobalConfiguration, _ *storage.Connection) {
		if cfg != nil {
			cfg.Experimental.ScimEnabled = true
		}
	}, WithSCIMUserRepository(users))
	require.NoError(t, err)
	defer api.db.Close()

	suite.Run(t, &SCIMUsersTestSuite{API: api, Config: config, Users: users})
}

func (ts *SCIMUsersTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))

	ts.TenantA = ts.buildTenant("example.com", 3)
	ts.TenantB = ts.buildTenant("example.org", 3)
}

func (ts *SCIMUsersTestSuite) TestGetUser() {
	ts.Run("returns the user that belongs to the requested provider", func() {
		user := ts.TenantA.users[0]

		w := ts.TenantA.get(user.ID)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.Equal(ts.T(), protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(ts.T(), fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": %q,
			"meta": {
				"resourceType": "User",
				"created": %q,
				"lastModified": %q,
				"location": "%s/scim/v2/Users/%s"
			}
		}`,
			core.SchemaUser,
			user.ID,
			user.UserName,
			user.Meta.Created.Format(time.RFC3339Nano),
			user.Meta.LastModified.Format(time.RFC3339Nano),
			ts.Config.API.ExternalURL, user.ID,
		), w.Body.String())
	})

	ts.Run("scopes each provider to its own users", func() {
		require.Equal(ts.T(), http.StatusOK, ts.TenantA.get(ts.TenantA.users[0].ID).Code)
		require.Equal(ts.T(), http.StatusNotFound, ts.TenantB.get(ts.TenantA.users[0].ID).Code)

		require.Equal(ts.T(), http.StatusOK, ts.TenantB.get(ts.TenantB.users[0].ID).Code)
		require.Equal(ts.T(), http.StatusNotFound, ts.TenantA.get(ts.TenantB.users[0].ID).Code)
	})
}

func (ts *SCIMUsersTestSuite) TestListUsers() {
	ts.Run("returns every user the provider has provisioned", func() {
		w := ts.TenantA.list("")

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.Equal(ts.T(), protocol.MediaType, w.Header().Get("Content-Type"))

		body := ts.decode(w)
		require.Equal(ts.T(), []core.SchemaURI{protocol.SchemaListResponse}, body.Schemas)
		require.Equal(ts.T(), 3, body.TotalResults)
		require.Equal(ts.T(), 1, body.StartIndex)
		require.Equal(ts.T(), 3, body.ItemsPerPage)
		require.ElementsMatch(ts.T(), ts.TenantA.userIDs(), resourceIDs(body))
	})

	ts.Run("scopes the collection to the requesting provider", func() {
		require.ElementsMatch(ts.T(), ts.TenantA.userIDs(), resourceIDs(ts.decode(ts.TenantA.list(""))))
		require.ElementsMatch(ts.T(), ts.TenantB.userIDs(), resourceIDs(ts.decode(ts.TenantB.list(""))))
	})

	ts.Run("refuses a request without credentials", func() {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		w := httptest.NewRecorder()

		ts.API.handler.ServeHTTP(w, r)

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
	})

	ts.Run("refuses a request for a provider that does not exist", func() {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		w := httptest.NewRecorder()

		r.Header.Set("Authorization", "Bearer "+ts.TenantA.token)
		r.Header.Set(scim.ProviderHeaderName, uuid.Must(uuid.NewV4()).String())
		ts.API.handler.ServeHTTP(w, r)

		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		require.Equal(ts.T(), protocol.MediaType, w.Header().Get("Content-Type"))
	})
}

func resourceIDs(body *protocol.ListResponse[core.User]) []string {
	ids := make([]string, 0, len(body.Resources))
	for _, resource := range body.Resources {
		ids = append(ids, resource.ID)
	}
	return ids
}

func (ts *SCIMUsersTestSuite) decode(w *httptest.ResponseRecorder) *protocol.ListResponse[core.User] {
	ts.T().Helper()

	body := &protocol.ListResponse[core.User]{}
	require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), body))
	return body
}

func (ts *SCIMUsersTestSuite) buildTenant(domain string, users int) *tenant {
	ts.T().Helper()

	id := uuid.Must(uuid.NewV4()).String()
	provider := &models.SSOProvider{
		SAMLProvider: models.SAMLProvider{
			EntityID:    "https://example.com/saml/metadata/" + id,
			MetadataXML: "<example />",
		},
		SSODomains: []models.SSODomain{{Domain: domain}},
	}
	require.NoError(ts.T(), ts.API.db.Eager().Create(provider))

	tn := &tenant{
		handler:  ts.API.handler,
		provider: provider,
		domain:   domain,
		token:    ts.signClaims(&AccessTokenClaims{Role: "supabase_admin"}),
	}
	for range users {
		tn.users = append(tn.users, ts.buildUser(tn, uuid.Must(uuid.NewV4()).String()))
	}

	return tn
}

func (ts *SCIMUsersTestSuite) buildUser(t *tenant, username string) *core.User {
	ts.T().Helper()

	id := uuid.Must(uuid.NewV4()).String()
	now := time.Now()
	user := &core.User{
		Schemas:  []core.SchemaURI{core.SchemaUser},
		ID:       id,
		UserName: username + "@" + t.domain,
		Meta:     core.NewMetaForID(ts.baseURL(), core.KindUser, id, now, now),
	}
	ts.Users.Put(t.provider.ID.String(), user)

	return user
}

func (ts *SCIMUsersTestSuite) baseURL() string {
	return core.Join(ts.Config.API.ExternalURL, scim.BasePath)
}

func (ts *SCIMUsersTestSuite) signClaims(claims *AccessTokenClaims) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	return token
}
