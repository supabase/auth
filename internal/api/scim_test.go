package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimServiceProviderConfigPath = "/scim/v2/ServiceProviderConfig"
	scimResourceTypesPath         = "/scim/v2/ResourceTypes"
	scimSchemasPath               = "/scim/v2/Schemas"
	scimUsersPath                 = "/scim/v2/Users"
)

var scimPaths = []string{
	scimServiceProviderConfigPath,
	scimResourceTypesPath,
	scimSchemasPath,
}

func TestSCIM(t *testing.T) {
	t.Run("Disabled by default", func(t *testing.T) {
		api, _, err := setupAPIForTest()
		require.NoError(t, err)

		require.False(t, api.config.SSO.SCIM.Enabled)

		for _, path := range scimPaths {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, "application/json", w.Header().Get("Content-Type"))
			require.JSONEq(t, `{"code":404,"error_code":"feature_disabled","msg":"SCIM server is disabled"}`, w.Body.String())
		}

		t.Run("Unknown endpoints stay hidden while disabled", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.NotContains(t, w.Body.String(), protocol.SchemaError)
		})
	})

	t.Run("Can be enabled", func(t *testing.T) {
		api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
			if config != nil {
				config.SSO.SCIM.Enabled = true
			}
		})
		require.NoError(t, err)

		require.True(t, api.config.SSO.SCIM.Enabled)

		provider, token := createSSOProviderWithSCIMToken(t, api.db)

		t.Run(scimServiceProviderConfigPath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimServiceProviderConfigPath, nil)
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+token)
			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), core.SchemaServiceProviderConfig)
		})

		for _, path := range []string{scimResourceTypesPath, scimSchemasPath} {
			t.Run(path, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				w := httptest.NewRecorder()

				r.Header.Set("Authorization", "Bearer "+token)
				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), protocol.SchemaListResponse)
			})

			t.Run(path+" rejects filter query parameter", func(t *testing.T) {
				filter := url.Values{"filter": {`name eq "User"`}}.Encode()
				r := httptest.NewRequest(http.MethodGet, path+"?"+filter, nil)
				w := httptest.NewRecorder()

				r.Header.Set("Authorization", "Bearer "+token)
				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusForbidden, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), protocol.SchemaError)
			})
		}

		t.Run("Every route is served by the SCIM server", func(t *testing.T) {
			for _, tc := range []struct{ method, path string }{
				{http.MethodGet, scimServiceProviderConfigPath},
				{http.MethodGet, scimResourceTypesPath},
				{http.MethodGet, scimResourceTypesPath + "/User"},
				{http.MethodGet, scimSchemasPath},
				{http.MethodGet, scimSchemasPath + "/" + string(core.SchemaUser)},
				{http.MethodGet, scimUsersPath},
				{http.MethodPost, scimUsersPath},
				{http.MethodGet, scimUsersPath + "/missing"},
				{http.MethodPut, scimUsersPath + "/missing"},
				{http.MethodPatch, scimUsersPath + "/missing"},
				{http.MethodDelete, scimUsersPath + "/missing"},
			} {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
					w := httptest.NewRecorder()

					r.Header.Set("Authorization", "Bearer "+token)
					api.handler.ServeHTTP(w, r)

					require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"), w.Body.String())
				})
			}
		})

		t.Run("Requires an active SCIM token", func(t *testing.T) {
			revoked, revokedToken, err := models.CreateSCIMToken(api.db, provider, nil)
			require.NoError(t, err)
			require.NoError(t, revoked.Revoke(api.db))

			expiresAt := time.Now().Add(time.Hour)
			expired, expiredToken, err := models.CreateSCIMToken(api.db, provider, &expiresAt)
			require.NoError(t, err)
			require.NoError(t, api.db.RawQuery(
				"UPDATE "+expired.TableName()+" SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = ?", expired.ID,
			).Exec())

			for _, tc := range []struct{ name, authorization string }{
				{"missing", ""},
				{"basic", "Basic " + token},
				{"malformed", "Bearer notatoken"},
				{"unknown", "Bearer scim_0000000000000000000000000000000000000000"},
				{"revoked", "Bearer " + revokedToken},
				{"expired", "Bearer " + expiredToken},
			} {
				for _, path := range []string{scimResourceTypesPath, scimSchemasPath, scimUsersPath} {
					t.Run(tc.name+" "+path, func(t *testing.T) {
						r := httptest.NewRequest(http.MethodGet, path, nil)
						if tc.authorization != "" {
							r.Header.Set("Authorization", tc.authorization)
						}
						w := httptest.NewRecorder()

						api.handler.ServeHTTP(w, r)

						require.Equal(t, http.StatusUnauthorized, w.Code)
						require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
						require.True(t, strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer"))
					})
				}

				t.Run(tc.name+" "+scimServiceProviderConfigPath, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodGet, scimServiceProviderConfigPath, nil)
					if tc.authorization != "" {
						r.Header.Set("Authorization", tc.authorization)
					}
					w := httptest.NewRecorder()

					api.handler.ServeHTTP(w, r)

					require.Equal(t, http.StatusOK, w.Code)
					require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				})
			}
		})

		t.Run("Records when a token is used", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimUsersPath, nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)
			require.Equal(t, http.StatusOK, w.Code)

			found, err := models.FindSCIMTokenByPrefix(api.db, provider.ID, token[:12])
			require.NoError(t, err)
			require.NotNil(t, found.LastUsedAt)
		})

		t.Run("Returns a SCIM 404 for an unknown endpoint", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+token)
			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), protocol.SchemaError)
		})

		t.Run("Returns a SCIM 405 for an unsupported method", func(t *testing.T) {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				for _, path := range scimPaths {
					t.Run(method+" "+path, func(t *testing.T) {
						r := httptest.NewRequest(method, path, nil)
						w := httptest.NewRecorder()

						r.Header.Set("Authorization", "Bearer "+token)
						api.handler.ServeHTTP(w, r)

						require.Equal(t, http.StatusMethodNotAllowed, w.Code)
						require.Equal(t, "GET, HEAD", w.Header().Get("Allow"))
						require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
					})
				}
			}

			for _, tc := range []struct {
				method, path string
				allow        string
			}{
				{http.MethodPut, scimUsersPath, "GET, HEAD, POST"},
				{http.MethodPost, scimUsersPath + "/missing", "DELETE, GET, HEAD, PATCH, PUT"},
			} {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					r := httptest.NewRequest(tc.method, tc.path, nil)
					w := httptest.NewRecorder()

					r.Header.Set("Authorization", "Bearer "+token)
					api.handler.ServeHTTP(w, r)

					require.Equal(t, http.StatusMethodNotAllowed, w.Code)
					require.Equal(t, tc.allow, w.Header().Get("Allow"))
					require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				})
			}
		})
	})
}

const scimValidToken = "scim_valid"

func TestSCIMServer(t *testing.T) {
	srv := newSCIMServerFor("http://localhost:9999")
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		w := scimServe(t, newSCIMServerFor("https://auth.example.com/"), http.MethodGet, scimBasePath+"/ServiceProviderConfig", "")

		meta := scimDecode(t, w)["meta"].(map[string]any)
		require.Equal(t, "https://auth.example.com"+scimBasePath+"/ServiceProviderConfig", meta["location"])
	})

	t.Run("ServiceProviderConfig", func(t *testing.T) {
		w := scimServe(t, srv, http.MethodGet, scimBasePath+"/ServiceProviderConfig", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, scimFixture(t, "service_provider_config.json"), w.Body.String())
	})

	t.Run("ResourceTypes", func(t *testing.T) {
		w := scimServe(t, srv, http.MethodGet, scimBasePath+"/ResourceTypes", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		body := scimDecode(t, w)
		require.EqualValues(t, 2, body["totalResults"])
		resources := map[string]map[string]any{}
		for _, resource := range body["Resources"].([]any) {
			resources[resource.(map[string]any)["id"].(string)] = resource.(map[string]any)
		}
		user := resources["User"]
		require.Equal(t, "/Users", user["endpoint"])
		require.Equal(t, string(core.SchemaUser), user["schema"])
		extension := user["schemaExtensions"].([]any)[0].(map[string]any)
		require.Equal(t, string(core.SchemaEnterpriseUser), extension["schema"])
		group := resources["Group"]
		require.Equal(t, "/Groups", group["endpoint"])
		require.Equal(t, string(core.SchemaGroup), group["schema"])
		require.Empty(t, group["schemaExtensions"])
	})

	for _, id := range []string{"User", "Group"} {
		t.Run("ResourceTypes/"+id, func(t *testing.T) {
			w := scimServe(t, srv, http.MethodGet, scimBasePath+"/ResourceTypes/"+id, "")

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, id, scimDecode(t, w)["id"])
		})
	}

	t.Run("Schemas", func(t *testing.T) {
		w := scimServe(t, srv, http.MethodGet, scimBasePath+"/Schemas", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		body := scimDecode(t, w)
		require.EqualValues(t, 3, body["totalResults"])
		ids := []string{}
		for _, resource := range body["Resources"].([]any) {
			ids = append(ids, resource.(map[string]any)["id"].(string))
		}
		require.ElementsMatch(t, []string{string(core.SchemaUser), string(core.SchemaEnterpriseUser), string(core.SchemaGroup)}, ids)
	})

	t.Run("Schemas/{id}", func(t *testing.T) {
		for _, id := range []core.SchemaURI{core.SchemaUser, core.SchemaEnterpriseUser, core.SchemaGroup} {
			w := scimServe(t, srv, http.MethodGet, scimBasePath+"/Schemas/"+string(id), "")

			require.Equal(t, http.StatusOK, w.Code)
			body := scimDecode(t, w)
			require.Equal(t, string(id), body["id"])
			location := "http://localhost:9999" + scimBasePath + "/Schemas/" + string(id)
			require.Equal(t, location, body["meta"].(map[string]any)["location"])
			require.Equal(t, location, w.Header().Get("Content-Location"))
		}
	})

	t.Run("Schemas/{id} location uses the external URL prefix", func(t *testing.T) {
		w := scimServe(t, newSCIMServerFor("https://project.supabase.co/auth/v1"), http.MethodGet, scimBasePath+"/Schemas/"+string(core.SchemaUser), "")

		require.Equal(t, http.StatusOK, w.Code)
		location := "https://project.supabase.co/auth/v1" + scimBasePath + "/Schemas/" + string(core.SchemaUser)
		require.Equal(t, location, scimDecode(t, w)["meta"].(map[string]any)["location"])
		require.Equal(t, location, w.Header().Get("Content-Location"))
	})

	t.Run("Schemas/User advertises the full RFC 7643 User attributes", func(t *testing.T) {
		w := scimServe(t, srv, http.MethodGet, scimBasePath+"/Schemas/"+string(core.SchemaUser), "")

		require.Equal(t, http.StatusOK, w.Code)
		names := []string{}
		for _, attribute := range scimDecode(t, w)["attributes"].([]any) {
			names = append(names, attribute.(map[string]any)["name"].(string))
		}
		for _, name := range []string{"userName", "name", "displayName", "title", "active", "emails", "phoneNumbers", "groups", "roles"} {
			require.Contains(t, names, name)
		}
	})

	for _, path := range []string{"/ResourceTypes", "/Schemas"} {
		t.Run(path+" rejects filter query parameter", func(t *testing.T) {
			query := url.Values{"filter": {`name eq "User"`}}.Encode()
			w := scimServe(t, srv, http.MethodGet, scimBasePath+path+"?"+query, "")

			require.Equal(t, http.StatusForbidden, w.Code)
			require.JSONEq(t, scimFixture(t, "filter_forbidden.json"), w.Body.String())
		})
	}

	t.Run("requires a bearer token", func(t *testing.T) {
		for _, tc := range []struct {
			name, authorization string
			status              int
			challenge           string
		}{
			{"missing header", "", http.StatusUnauthorized, `Bearer realm="scim"`},
			{"wrong scheme", "Basic " + scimValidToken, http.StatusUnauthorized, `Bearer realm="scim"`},
			{"empty token", "Bearer ", http.StatusBadRequest, `Bearer realm="scim", error="invalid_request", error_description="missing bearer token"`},
			{"invalid token", "Bearer scim_invalid", http.StatusUnauthorized, `Bearer realm="scim", error="invalid_token", error_description="The access token is invalid"`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := scimServe(t, srv, http.MethodGet, scimBasePath+"/Users", "", "Authorization", tc.authorization)

				require.Equal(t, tc.status, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.Equal(t, tc.challenge, w.Header().Get("WWW-Authenticate"))
			})
		}
	})
}

type SCIMTestSuite struct {
	suite.Suite
	API    *API
	TokenA string
	TokenB string
	A      *models.SSOProvider
	B      *models.SSOProvider
}

func TestSCIMSuite(t *testing.T) {
	api, _ := setupSCIMAPI(t, func(config *conf.GlobalConfiguration) {
		config.RateLimitScim = 1_000_000
	})
	defer func() { require.NoError(t, api.db.Close()) }()

	suite.Run(t, &SCIMTestSuite{API: api})
}

func (ts *SCIMTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))
	ts.A, ts.TokenA = ts.provider()
	ts.B, ts.TokenB = ts.provider()
}

func (ts *SCIMTestSuite) provider() (*models.SSOProvider, string) {
	return createSSOProviderWithSCIMToken(ts.T(), ts.API.db)
}

func (ts *SCIMTestSuite) do(token, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	return ts.doAs(protocol.MediaType, token, method, path, body)
}

func (ts *SCIMTestSuite) doAs(contentType, token, method, path, body string, headers ...string) (*httptest.ResponseRecorder, map[string]any) {
	w := ts.serve(contentType, token, method, path, body, headers...)

	var decoded map[string]any
	if w.Body.Len() > 0 {
		require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &decoded), w.Body.String())
	}
	return w, decoded
}

func (ts *SCIMTestSuite) serve(contentType, token, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", contentType)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
}

func setupSCIMAPI(t *testing.T, tweak func(*conf.GlobalConfiguration)) (*API, *conf.GlobalConfiguration) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			if tweak != nil {
				tweak(config)
			}
		}
	})
	require.NoError(t, err)
	return api, config
}

func createSSOProvider(t require.TestingT, db *storage.Connection) *models.SSOProvider {
	provider := &models.SSOProvider{}
	require.NoError(t, db.Create(provider))
	return provider
}

func createSCIMEnabledProvider(t require.TestingT, db *storage.Connection) *models.SSOProvider {
	provider := createSSOProvider(t, db)
	_, err := models.EnableSCIM(db, provider.ID)
	require.NoError(t, err)
	return provider
}

func createSSOProviderWithSCIMToken(t require.TestingT, db *storage.Connection) (*models.SSOProvider, string) {
	provider := createSCIMEnabledProvider(t, db)
	_, token, err := models.CreateSCIMToken(db, provider, nil)
	require.NoError(t, err)
	return provider, token
}

func adminJWT(t require.TestingT, secret string) string {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(secret))
	require.NoError(t, err)
	return token
}

func serveAdmin(t require.TestingT, api *API, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Authorization", "Bearer "+adminJWT(t, api.config.JWT.Secret))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, r)
	return w
}

func queryAuditEntries(t require.TestingT, db *storage.Connection, where string, args ...any) []models.AuditLogEntry {
	entries := []models.AuditLogEntry{}
	require.NoError(t, db.Q().Where(where, args...).Order("created_at asc").All(&entries))
	return entries
}

func scimFixture(t *testing.T, file string) string {
	data, err := fs.ReadFile(os.DirFS("testdata/scim"), file)
	require.NoError(t, err)
	return string(data)
}

func newSCIMServerFor(externalURL string) *server.Server {
	validate := func(ctx context.Context, candidate string) (context.Context, error) {
		if candidate != scimValidToken {
			return ctx, server.ErrInvalidToken
		}
		return ctx, nil
	}
	return (&API{config: &conf.GlobalConfiguration{API: conf.APIConfiguration{ExternalURL: externalURL}}}).newSCIMServer(validate, nil)
}

func scimServe(t *testing.T, srv *server.Server, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", protocol.MediaType)
	r.Header.Set("Authorization", "Bearer "+scimValidToken)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func scimDecode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}
