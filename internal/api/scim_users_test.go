package api

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	scimCore "github.com/supabase/auth/internal/api/scim/core"
	scimProtocol "github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	minTenantUsers = 2
	maxTenantUsers = 5
)

type tenant struct {
	provider *models.SSOProvider
	users    []*models.User
	token    string
	domain   string
}

type SCIMUsersTestSuite struct {
	suite.Suite
	API     *API
	Config  *conf.GlobalConfiguration
	TenantA *tenant
	TenantB *tenant
}

func TestSCIMUsers(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(cfg *conf.GlobalConfiguration, _ *storage.Connection) {
		if cfg != nil {
			cfg.Experimental.ScimEnabled = true
		}
	})
	require.NoError(t, err)
	defer api.db.Close()

	suite.Run(t, &SCIMUsersTestSuite{API: api, Config: config})
}

func (ts *SCIMUsersTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))

	ts.TenantA = seedSCIMTenant(ts.T(), ts.API.db, "example.com")
	ts.TenantB = seedSCIMTenant(ts.T(), ts.API.db, "example.org")
}

func (ts *SCIMUsersTestSuite) get(id, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+id, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
}

func (ts *SCIMUsersTestSuite) TestGetUser() {
	ts.Run("returns the user that belongs to the token's provider", func() {
		user := ts.TenantA.users[0]

		w := ts.get(user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(ts.T(), fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": %q,
			"emails": [{"value": %q, "primary": true}],
			"meta": {
				"resourceType": "User",
				"created": %q,
				"lastModified": %q,
				"location": "%s/scim/v2/Users/%s"
			}
		}`,
			scimCore.SchemaUser,
			user.ID,
			user.GetEmail(),
			user.GetEmail(),
			user.CreatedAt.UTC().Format(time.RFC3339Nano),
			user.UpdatedAt.UTC().Format(time.RFC3339Nano),
			ts.Config.API.ExternalURL, user.ID,
		), w.Body.String())
	})

	ts.Run("returns every user the tenant provisioned", func() {
		require.Greater(ts.T(), len(ts.TenantA.users), 1)

		for _, user := range ts.TenantA.users {
			w := ts.get(user.ID.String(), ts.TenantA.token)

			require.Equal(ts.T(), http.StatusOK, w.Code, "user %s", user.ID)
			require.Contains(ts.T(), w.Body.String(), user.GetEmail())
		}
	})

	ts.Run("scopes each provider to its own users", func() {
		require.Equal(ts.T(), http.StatusOK, ts.get(ts.TenantA.users[0].ID.String(), ts.TenantA.token).Code)
		require.Equal(ts.T(), http.StatusNotFound, ts.get(ts.TenantA.users[0].ID.String(), ts.TenantB.token).Code)

		require.Equal(ts.T(), http.StatusOK, ts.get(ts.TenantB.users[0].ID.String(), ts.TenantB.token).Code)
		require.Equal(ts.T(), http.StatusNotFound, ts.get(ts.TenantB.users[0].ID.String(), ts.TenantA.token).Code)
	})

	ts.Run("omits name when the provider has no attribute mapping", func() {
		user := ts.TenantA.users[0]

		w := ts.get(user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.NotContains(ts.T(), w.Body.String(), `"name"`)
		require.Contains(ts.T(), w.Body.String(), fmt.Sprintf(`"userName":%q`, user.GetEmail()))
	})

	ts.Run("keeps custom claims out of the response", func() {
		user := seedSCIMUser(ts.T(), ts.API.db, ts.TenantA.provider, "custom@"+ts.TenantA.domain, map[string]interface{}{
			"custom_claims": map[string]interface{}{"department": "engineering"},
		})

		w := ts.get(user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.NotContains(ts.T(), w.Body.String(), "department")
		require.NotContains(ts.T(), w.Body.String(), "engineering")
	})

	ts.Run("identifies the resource by user id, not by the NameID", func() {
		opaque := seedSCIMUser(ts.T(), ts.API.db, ts.TenantA.provider, "persistent@"+ts.TenantA.domain, map[string]interface{}{
			"sub": uuid.Must(uuid.NewV4()).String(),
		})

		w := ts.get(opaque.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.Contains(ts.T(), w.Body.String(), fmt.Sprintf(`"id":%q`, opaque.ID))
	})

	ts.Run("maps the attributes when the provider has an attribute mapping", func() {
		user := seedSCIMUser(ts.T(), ts.API.db, ts.TenantA.provider, "stale@example.com", map[string]interface{}{
			"email":              "bjensen@example.com",
			"preferred_username": "bjensen",
			"name":               "Ms. Barbara Jane Jensen, III",
			"family_name":        "Jensen",
			"given_name":         "Barbara",
			"middle_name":        "Jane",
		})

		w := ts.get(user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.JSONEq(ts.T(), fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": "bjensen",
			"name": {
				"formatted": "Ms. Barbara Jane Jensen, III",
				"familyName": "Jensen",
				"givenName": "Barbara",
				"middleName": "Jane"
			},
			"emails": [{"value": "bjensen@example.com", "primary": true}],
			"meta": {
				"resourceType": "User",
				"created": %q,
				"lastModified": %q,
				"location": "%s/scim/v2/Users/%s"
			}
		}`,
			scimCore.SchemaUser,
			user.ID,
			user.CreatedAt.UTC().Format(time.RFC3339Nano),
			user.UpdatedAt.UTC().Format(time.RFC3339Nano),
			ts.Config.API.ExternalURL, user.ID,
		), w.Body.String())
	})
}

func (ts *SCIMUsersTestSuite) TestTenantIsolation() {
	ts.Run("hides every user belonging to another provider", func() {
		for _, user := range ts.TenantB.users {
			w := ts.get(user.ID.String(), ts.TenantA.token)

			require.Equal(ts.T(), http.StatusNotFound, w.Code, "user %s", user.ID)
			require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
		}
	})

	ts.Run("returns the same 404 for an unknown id", func() {
		unknown := ts.get(uuid.Must(uuid.NewV4()).String(), ts.TenantA.token)
		other := ts.get(ts.TenantB.users[0].ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusNotFound, unknown.Code)
		require.Equal(ts.T(), other.Body.String(), unknown.Body.String())
	})

	ts.Run("returns 404 for a malformed id", func() {
		w := ts.get("not-a-uuid", ts.TenantA.token)

		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
	})
}

func (ts *SCIMUsersTestSuite) TestAuthentication() {
	ts.Run("requires a bearer token", func() {
		w := ts.get(ts.TenantA.users[0].ID.String(), "")

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Equal(ts.T(), "Bearer", w.Header().Get("WWW-Authenticate"))
		require.Contains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
	})

	ts.Run("rejects an unknown token", func() {
		w := ts.get(ts.TenantA.users[0].ID.String(), uuid.Must(uuid.NewV4()).String())

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
		require.Equal(ts.T(), "Bearer", w.Header().Get("WWW-Authenticate"))
	})
}

func (ts *SCIMUsersTestSuite) TestRejectsADisabledProvider() {
	disabled := true
	ts.TenantB.provider.Disabled = &disabled
	require.NoError(ts.T(), ts.API.db.Update(ts.TenantB.provider))

	w := ts.get(ts.TenantB.users[0].ID.String(), ts.TenantB.token)

	require.Equal(ts.T(), http.StatusForbidden, w.Code)
	require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
}

func (ts *SCIMUsersTestSuite) TestStaysHiddenWhenTheFeatureFlagIsOff() {
	disabled, _, err := setupAPIForTest()
	require.NoError(ts.T(), err)

	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+ts.TenantA.users[0].ID.String(), nil)
	r.Header.Set("Authorization", "Bearer "+ts.TenantA.token)
	w := httptest.NewRecorder()
	disabled.handler.ServeHTTP(w, r)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)
	require.Equal(ts.T(), "application/json", w.Header().Get("Content-Type"))
	require.NotContains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
}

func seedSCIMTenant(t *testing.T, conn *storage.Connection, domain string) *tenant {
	t.Helper()

	id := uuid.Must(uuid.NewV4()).String()
	provider := &models.SSOProvider{
		SAMLProvider: models.SAMLProvider{
			EntityID:    "https://example.com/saml/metadata/" + id,
			MetadataXML: "<example />",
		},
		SSODomains: []models.SSODomain{{Domain: domain}},
	}
	token := uuid.Must(uuid.NewV4()).String()
	provider.UpdateSCIMToken(token)
	require.NoError(t, conn.Eager().Create(provider))

	count := minTenantUsers + rand.IntN(maxTenantUsers-minTenantUsers+1)

	users := make([]*models.User, 0, count)
	for range count {
		email := uuid.Must(uuid.NewV4()).String() + "@" + domain
		users = append(users, seedSCIMUser(t, conn, provider, email))
	}

	return &tenant{provider: provider, users: users, token: token, domain: domain}
}

func seedSCIMUser(t *testing.T, conn *storage.Connection, provider *models.SSOProvider, email string, extraClaims ...map[string]interface{}) *models.User {
	t.Helper()

	user, err := models.NewUser("", email, "", "authenticated", nil)
	require.NoError(t, err)
	user.IsSSOUser = true
	require.NoError(t, conn.Create(user))

	claims := map[string]interface{}{
		"iss":            provider.SAMLProvider.EntityID,
		"sub":            email,
		"email":          email,
		"email_verified": true,
		"phone_verified": false,
		"custom_claims":  map[string]interface{}{},
	}
	for _, extra := range extraClaims {
		for key, value := range extra {
			claims[key] = value
		}
	}

	identity, err := models.NewIdentity(user, provider.ProviderType(), claims)
	require.NoError(t, err)
	require.NoError(t, conn.Create(identity))

	return user
}
