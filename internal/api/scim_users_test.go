package api

import (
	"fmt"
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

type scimTenant struct {
	provider *models.SSOProvider
	user     *models.User
	token    string
}

type SCIMUsersTestSuite struct {
	suite.Suite
	API     *API
	Config  *conf.GlobalConfiguration
	TenantA *scimTenant
	TenantB *scimTenant
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

	ts.TenantA = seedSCIMTenant(ts.T(), ts.API.db, "scim_token_a", "a@example.com")
	ts.TenantB = seedSCIMTenant(ts.T(), ts.API.db, "scim_token_b", "b@example.com")
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
		w := ts.get(ts.TenantA.user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(ts.T(), fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": "a@example.com",
			"emails": [{"value": "a@example.com", "primary": true}],
			"meta": {
				"resourceType": "User",
				"created": %q,
				"lastModified": %q,
				"location": "%s/scim/v2/Users/%s"
			}
		}`,
			scimCore.SchemaUser,
			ts.TenantA.user.ID,
			ts.TenantA.user.CreatedAt.UTC().Format(time.RFC3339Nano),
			ts.TenantA.user.UpdatedAt.UTC().Format(time.RFC3339Nano),
			ts.Config.API.ExternalURL, ts.TenantA.user.ID,
		), w.Body.String())
	})

	ts.Run("scopes each provider to its own users", func() {
		require.Equal(ts.T(), http.StatusOK, ts.get(ts.TenantB.user.ID.String(), ts.TenantB.token).Code)
	})

	ts.Run("maps the attributes the provider supplied", func() {
		c := seedSCIMTenant(ts.T(), ts.API.db, "scim_token_c", "stale@example.com", map[string]interface{}{
			"email":              "bjensen@example.com",
			"preferred_username": "bjensen",
			"name":               "Ms. Barbara Jane Jensen, III",
			"family_name":        "Jensen",
			"given_name":         "Barbara",
		})

		w := ts.get(c.user.ID.String(), c.token)

		require.Equal(ts.T(), http.StatusOK, w.Code)
		require.JSONEq(ts.T(), fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": "bjensen",
			"name": {
				"formatted": "Ms. Barbara Jane Jensen, III",
				"familyName": "Jensen",
				"givenName": "Barbara"
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
			c.user.ID,
			c.user.CreatedAt.UTC().Format(time.RFC3339Nano),
			c.user.UpdatedAt.UTC().Format(time.RFC3339Nano),
			ts.Config.API.ExternalURL, c.user.ID,
		), w.Body.String())
	})
}

func (ts *SCIMUsersTestSuite) TestTenantIsolation() {
	ts.Run("hides a user belonging to another provider", func() {
		w := ts.get(ts.TenantB.user.ID.String(), ts.TenantA.token)

		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Contains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
	})

	ts.Run("returns the same 404 for an unknown id", func() {
		unknown := ts.get(uuid.Must(uuid.NewV4()).String(), ts.TenantA.token)
		other := ts.get(ts.TenantB.user.ID.String(), ts.TenantA.token)

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
		w := ts.get(ts.TenantA.user.ID.String(), "")

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
		require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Equal(ts.T(), "Bearer", w.Header().Get("WWW-Authenticate"))
		require.Contains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
	})

	ts.Run("rejects an unknown token", func() {
		w := ts.get(ts.TenantA.user.ID.String(), "scim_nope")

		require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
		require.Equal(ts.T(), "Bearer", w.Header().Get("WWW-Authenticate"))
	})
}

// Kept out of TestAuthentication because it mutates the seeded provider, which
// SetupTest only restores between suite methods.
func (ts *SCIMUsersTestSuite) TestRejectsADisabledProvider() {
	disabled := true
	ts.TenantB.provider.Disabled = &disabled
	require.NoError(ts.T(), ts.API.db.Update(ts.TenantB.provider))

	w := ts.get(ts.TenantB.user.ID.String(), ts.TenantB.token)

	require.Equal(ts.T(), http.StatusForbidden, w.Code)
	require.Equal(ts.T(), scimProtocol.MediaType, w.Header().Get("Content-Type"))
}

func (ts *SCIMUsersTestSuite) TestStaysHiddenWhenTheFeatureFlagIsOff() {
	disabled, _, err := setupAPIForTest()
	require.NoError(ts.T(), err)

	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+ts.TenantA.user.ID.String(), nil)
	r.Header.Set("Authorization", "Bearer "+ts.TenantA.token)
	w := httptest.NewRecorder()
	disabled.handler.ServeHTTP(w, r)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)
	require.Equal(ts.T(), "application/json", w.Header().Get("Content-Type"))
	require.NotContains(ts.T(), w.Body.String(), scimProtocol.SchemaError)
}

func seedSCIMTenant(t *testing.T, conn *storage.Connection, token, email string, extraClaims ...map[string]interface{}) *scimTenant {
	t.Helper()

	id := uuid.Must(uuid.NewV4()).String()
	provider := &models.SSOProvider{
		SAMLProvider: models.SAMLProvider{
			EntityID:    "https://example.com/saml/metadata/" + id,
			MetadataXML: "<example />",
		},
		SSODomains: []models.SSODomain{
			{Domain: id + ".local"},
		},
	}
	provider.UpdateSCIMToken(token)
	require.NoError(t, conn.Eager().Create(provider))

	user, err := models.NewUser("", email, "", "authenticated", nil)
	require.NoError(t, err)
	user.IsSSOUser = true
	require.NoError(t, conn.Create(user))

	claims := map[string]interface{}{
		"sub":   user.ID.String(),
		"email": email,
	}
	for _, extra := range extraClaims {
		for key, value := range extra {
			claims[key] = value
		}
	}

	identity, err := models.NewIdentity(user, provider.ProviderType(), claims)
	require.NoError(t, err)
	require.NoError(t, conn.Create(identity))

	return &scimTenant{provider: provider, user: user, token: token}
}
