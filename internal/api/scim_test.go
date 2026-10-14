package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/models"
)

const (
	scimServiceProviderConfigPath = "/scim/v2/ServiceProviderConfig"
	scimResourceTypesPath         = "/scim/v2/ResourceTypes"
	scimSchemasPath               = "/scim/v2/Schemas"
	scimUsersPath                 = "/scim/v2/Users"
	scimGroupsPath                = "/scim/v2/Groups"
	scimMissingID                 = "00000000-0000-0000-0000-000000000000"
)

var scimPaths = []string{
	scimServiceProviderConfigPath,
	scimResourceTypesPath,
	scimSchemasPath,
}

// RFC 7644 sections 2 and 4, RFC 7643 sections 5 to 7
func TestSCIMService(t *testing.T) {
	t.Run("Discovery", func(t *testing.T) {
		t.Run("Disabled by default", func(t *testing.T) {
			c := scimClient{inst: newSCIMInstance(t, func(config *conf.GlobalConfiguration) {
				config.SSO.SCIM.Enabled = false
			})}

			for _, path := range append(scimPaths, "/scim/v2/Unknown") {
				res := c.send(t, scimRequest(t, http.MethodGet, path, nil))
				require.Equal(t, http.StatusNotFound, res.StatusCode)
				require.Equal(t, "application/json", res.Header.Get("Content-Type"))
				require.JSONEq(t, `{"code":404,"error_code":"feature_disabled","msg":"SCIM server is disabled"}`, string(scimBody(t, res)))
			}
		})

		c := newSCIMClient(t, nil)

		for _, tc := range []struct{ path, schema string }{
			{scimServiceProviderConfigPath, string(core.SchemaServiceProviderConfig)},
			{scimResourceTypesPath, string(protocol.SchemaListResponse)},
			{scimSchemasPath, string(protocol.SchemaListResponse)},
		} {
			t.Run("GET "+tc.path, func(t *testing.T) {
				res := c.get(t, tc.path)
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
				require.Contains(t, string(scimBody(t, res)), tc.schema)
			})
		}

		t.Run("ServiceProviderConfig matches the fixture", func(t *testing.T) {
			fixture := scimFixture(t, "service_provider_config.json")

			res := c.get(t, scimServiceProviderConfigPath)
			require.JSONEq(t, string(fixture), string(scimBody(t, res)))
		})

		t.Run("Location trims a trailing slash from the external URL", func(t *testing.T) {
			c := newSCIMClient(t, func(config *conf.GlobalConfiguration) {
				config.API.ExternalURL = "https://auth.example.com/"
			})

			res := c.get(t, scimServiceProviderConfigPath)
			var body struct {
				Meta struct {
					Location string `json:"location"`
				} `json:"meta"`
			}
			require.NoError(t, json.Unmarshal(scimBody(t, res), &body))
			require.Equal(t, "https://auth.example.com"+scimServiceProviderConfigPath, body.Meta.Location)
		})

		t.Run("Schemas/User advertises the RFC 7643 User attributes", func(t *testing.T) {
			res := c.get(t, scimSchemasPath+"/"+string(core.SchemaUser))
			require.Equal(t, http.StatusOK, res.StatusCode)

			var schema struct {
				Attributes []struct {
					Name string `json:"name"`
				} `json:"attributes"`
			}
			require.NoError(t, json.Unmarshal(scimBody(t, res), &schema))
			names := []string{}
			for _, attribute := range schema.Attributes {
				names = append(names, attribute.Name)
			}
			for _, name := range []string{"userName", "name", "displayName", "title", "active", "emails", "phoneNumbers", "groups", "roles"} {
				require.Contains(t, names, name)
			}
		})

		for _, path := range []string{scimResourceTypesPath, scimSchemasPath} {
			t.Run(path+" rejects the filter query parameter", func(t *testing.T) {
				res := c.get(t, path+"?"+url.Values{"filter": {`name eq "User"`}}.Encode())
				requireSCIMError(t, res, http.StatusForbidden, "")
			})
		}

		t.Run("Unknown endpoint returns a SCIM 404", func(t *testing.T) {
			res := c.get(t, "/scim/v2/Unknown")
			requireSCIMError(t, res, http.StatusNotFound, "")
		})

		t.Run("Unsupported method returns a SCIM 405", func(t *testing.T) {
			type disallowed struct{ method, path, allow string }
			cases := []disallowed{
				{http.MethodPut, scimUsersPath, "GET, HEAD, POST"},
				{http.MethodPost, scimUsersPath + "/" + scimMissingID, "DELETE, GET, HEAD, PATCH, PUT"},
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				for _, path := range scimPaths {
					cases = append(cases, disallowed{method, path, "GET, HEAD"})
				}
			}
			for _, tc := range cases {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					res := c.do(t, tc.method, tc.path, nil)
					require.Equal(t, http.StatusMethodNotAllowed, res.StatusCode)
					require.Equal(t, tc.allow, res.Header.Get("Allow"))
					require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
				})
			}
		})
	})

	t.Run("Authentication", func(t *testing.T) {
		c := newSCIMClient(t, nil)

		for _, tc := range []struct {
			name, authorization string
			status              int
			challenge           string
		}{
			{"missing header", "", http.StatusUnauthorized, `Bearer realm="scim"`},
			{"wrong scheme", "Basic " + c.token, http.StatusUnauthorized, `Bearer realm="scim"`},
			{"empty token", "Bearer ", http.StatusBadRequest, `Bearer realm="scim", error="invalid_request", error_description="missing bearer token"`},
			{"invalid token", "Bearer scim_invalid", http.StatusUnauthorized, `Bearer realm="scim", error="invalid_token", error_description="The access token is invalid"`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := scimRequest(t, http.MethodGet, scimUsersPath, nil)
				if tc.authorization != "" {
					req.Header.Set("Authorization", tc.authorization)
				}
				res := c.send(t, req)

				require.Equal(t, tc.status, res.StatusCode)
				require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
				require.Equal(t, tc.challenge, res.Header.Get("WWW-Authenticate"))
			})
		}

		t.Run("rejects a revoked token", func(t *testing.T) {
			token, raw, err := models.CreateSCIMToken(c.inst.Conn, uuid.UUID(c.provider.ID), nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, c.as(raw).get(t, scimUsersPath).StatusCode)

			res := c.admin(t, http.MethodDelete, "/admin/sso/providers/"+c.provider.ID.String()+"/scim/tokens/"+token.ID.String(), nil)
			require.Equal(t, http.StatusOK, res.StatusCode)

			routes := scimItemRoutes(scimMissingID, scimMissingID)
			for _, base := range []string{scimUsersPath, scimGroupsPath} {
				routes = append(routes, scimRoute{http.MethodGet, base, nil}, scimRoute{http.MethodPost, base, map[string]any{}}, scimRoute{http.MethodPost, base + "/.search", map[string]any{}})
			}
			for _, route := range routes {
				require.Equal(t, http.StatusUnauthorized, c.as(raw).do(t, route.method, route.path, route.body).StatusCode, route)
			}
		})

		t.Run("rejects a token after SCIM is disabled for the provider", func(t *testing.T) {
			other := newSCIMClient(t, nil)
			require.Equal(t, http.StatusOK, other.get(t, scimUsersPath).StatusCode)

			res := other.admin(t, http.MethodDelete, "/admin/sso/providers/"+other.provider.ID.String()+"/scim", nil)
			require.Equal(t, http.StatusOK, res.StatusCode)

			require.Equal(t, http.StatusUnauthorized, other.get(t, scimUsersPath).StatusCode)
		})
	})

	t.Run("Admin tokens", func(t *testing.T) {
		c := newSCIMClient(t, nil)
		scimPath := "/admin/sso/providers/" + c.provider.ID.String() + "/scim"
		tokensPath := scimPath + "/tokens"
		status := func(t *testing.T, method string) api.AdminSCIMStatusResponse {
			res := c.admin(t, method, scimPath, nil)
			require.Equal(t, http.StatusOK, res.StatusCode)
			return scimDecode[api.AdminSCIMStatusResponse](t, res)
		}
		create := func(t *testing.T, body any) api.AdminSCIMTokenCreateResponse {
			res := c.admin(t, http.MethodPost, tokensPath, body)
			require.Equal(t, http.StatusCreated, res.StatusCode)
			return scimDecode[api.AdminSCIMTokenCreateResponse](t, res)
		}
		revoke := func(t *testing.T, id string) *http.Response {
			return c.admin(t, http.MethodDelete, tokensPath+"/"+id, nil)
		}

		t.Run("GET shows status and active tokens", func(t *testing.T) {
			got := status(t, http.MethodGet)
			require.True(t, got.Enabled)
			require.NotEmpty(t, got.BaseURL)
			require.NotEmpty(t, got.Tokens)
			for _, token := range got.Tokens {
				require.Nil(t, token.RevokedAt)
			}
		})

		t.Run("DELETE and POST toggle SCIM and repeat safely", func(t *testing.T) {
			for _, step := range []struct {
				method  string
				enabled bool
			}{{http.MethodDelete, false}, {http.MethodDelete, false}, {http.MethodPost, true}, {http.MethodPost, true}} {
				require.Equal(t, step.enabled, status(t, step.method).Enabled, step.method)
			}
		})

		t.Run("POST tokens creates a token that authenticates", func(t *testing.T) {
			token := create(t, nil)
			require.True(t, strings.HasPrefix(token.Token, "scim_"))
			require.Equal(t, token.Token[:len(token.Prefix)], token.Prefix)
			require.NotEmpty(t, token.BaseURL)
			require.Nil(t, token.ExpiresAt)
			require.Equal(t, http.StatusOK, c.as(token.Token).get(t, scimUsersPath).StatusCode)
		})

		t.Run("POST tokens with expires_at", func(t *testing.T) {
			expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			token := create(t, map[string]any{"expires_at": expiresAt})
			require.NotNil(t, token.ExpiresAt)
			require.True(t, expiresAt.Equal(*token.ExpiresAt))

			res := c.admin(t, http.MethodPost, tokensPath, map[string]any{"expires_at": time.Now().Add(-time.Hour)})
			require.Equal(t, http.StatusBadRequest, res.StatusCode)
		})

		t.Run("DELETE token rejects an id that is not a uuid", func(t *testing.T) {
			require.Equal(t, http.StatusNotFound, revoke(t, "not-a-uuid").StatusCode)
		})

		t.Run("DELETE token revokes once and repeats safely", func(t *testing.T) {
			token := create(t, nil)
			first := revoke(t, token.ID.String())
			require.Equal(t, http.StatusOK, first.StatusCode)
			revoked := scimDecode[models.SCIMToken](t, first)
			require.NotNil(t, revoked.RevokedAt)

			second := revoke(t, token.ID.String())
			require.Equal(t, http.StatusOK, second.StatusCode)
			require.Equal(t, revoked, scimDecode[models.SCIMToken](t, second))

			require.Equal(t, http.StatusUnauthorized, c.as(token.Token).get(t, scimUsersPath).StatusCode)
			require.NotContains(t, status(t, http.MethodGet).Tokens, revoked)

			res := c.admin(t, http.MethodGet, tokensPath, nil)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Contains(t, scimDecode[api.AdminSCIMTokenListResponse](t, res).Tokens, revoked)
		})

		t.Run("DELETE token returns 404 for a token it cannot find", func(t *testing.T) {
			other := newSCIMClient(t, nil)
			foreign, _, err := models.CreateSCIMToken(other.inst.Conn, uuid.UUID(other.provider.ID), nil)
			require.NoError(t, err)

			for _, id := range []string{uuid.NewV7().String(), "not-a-uuid", foreign.ID.String()} {
				require.Equal(t, http.StatusNotFound, revoke(t, id).StatusCode, id)
			}
		})
	})
}

// RFC 7644 sections 3.1 to 3.6, RFC 7643 sections 4.1 and 4.3
func TestSCIMUsers(t *testing.T) {
	c := newSCIMClient(t, nil)

	t.Run("Create", func(t *testing.T) {
		t.Run("POST creates a user", func(t *testing.T) {
			userName := scimUserName("bjensen")
			res := c.do(t, http.MethodPost, scimUsersPath, newSCIMUser(userName, "Barbara", "Jensen"))

			require.Equal(t, http.StatusCreated, res.StatusCode)
			require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
			user := scimDecode[core.User](t, res)
			require.NotEmpty(t, user.ID)
			require.Equal(t, userName, user.UserName)
			require.Equal(t, new(true), user.Active)
			require.Equal(t, core.Name{GivenName: "Barbara", FamilyName: "Jensen"}, user.Name)
			require.Equal(t, user.Meta.Location, res.Header.Get("Location"))
		})

		t.Run("POST ignores read-only groups", func(t *testing.T) {
			group := c.createGroup(t, "readonly-"+uuid.NewV7().String())
			body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			body["groups"] = []map[string]any{{"value": group.ID}}
			user := scimCreate[core.User](t, c, scimUsersPath, body)
			require.Empty(t, user.Groups)
			require.Empty(t, c.user(t, user.ID).Groups)
		})

		t.Run("POST assigns meta and ignores the client's meta", func(t *testing.T) {
			body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			body["meta"] = map[string]any{"resourceType": "Group", "created": "2000-01-01T00:00:00Z", "lastModified": "2000-01-01T00:00:00Z", "location": "https://evil.example.com/Users/1"}
			user := scimCreate[core.User](t, c, scimUsersPath, body)

			require.Equal(t, core.ResourceTypeName("User"), user.Meta.ResourceType)
			require.Equal(t, user.Meta.Created, user.Meta.LastModified)
			require.Greater(t, user.Meta.Created.Year(), 2000)
			location, err := url.Parse(user.Meta.Location)
			require.NoError(t, err)
			require.Equal(t, user, scimDecode[core.User](t, c.get(t, location.Path)))
		})

		t.Run("POST accepts schemas in any order", func(t *testing.T) {
			body := newSCIMReport(scimMissingID)
			body["schemas"] = []string{string(core.SchemaEnterpriseUser), string(core.SchemaUser)}
			user := scimCreate[core.User](t, c, scimUsersPath, body)
			require.Equal(t, "Tour Operations", c.user(t, user.ID).EnterpriseUser.Department)
		})

		t.Run("POST creates a minimal user", func(t *testing.T) {
			res := c.do(t, http.MethodPost, scimUsersPath, map[string]any{"schemas": []string{string(core.SchemaUser)}, "userName": scimUserName("min")})
			require.Equal(t, http.StatusCreated, res.StatusCode)
			require.NotEmpty(t, scimDecode[core.User](t, res).ID)
		})

		t.Run("POST creates a user with every attribute", func(t *testing.T) {
			manager := c.createUser(t, scimUserName("boss"))
			body := newSCIMFullUser(scimUserName("bjensen"), uuid.NewV7().String(), manager.ID)
			user := scimCreate[core.User](t, c, scimUsersPath, body)

			require.Equal(t, user, c.user(t, user.ID))
			require.Equal(t, "Ms. Barbara J Jensen III", user.Name.Formatted)
			require.Equal(t, "Tour Guide", user.Title)
			require.Equal(t, new(false), user.Active)
			require.Empty(t, user.Password)
			require.Equal(t, "babs@jensen.org", user.Emails[0].Value)
			require.Equal(t, "555-555-8377", user.PhoneNumbers[0].Value)
			require.Equal(t, "Hollywood", user.Addresses[0].Locality)
			require.Equal(t, "tour-guide-badge", user.Entitlements[0].Value)
			require.Equal(t, "guide", user.Roles[0].Value)
			require.Equal(t, "Tour Operations", user.EnterpriseUser.Department)
			require.Equal(t, manager.ID, user.EnterpriseUser.Manager.Value)
		})

		t.Run("POST rejects an invalid body", func(t *testing.T) {
			for name, tc := range map[string]struct {
				body     map[string]any
				scimType scimerrors.ErrorType
			}{
				"active is not a boolean": {map[string]any{"userName": scimUserName("bad"), "active": "yes"}, scimerrors.InvalidSyntax},
				"empty userName":          {map[string]any{"userName": ""}, scimerrors.InvalidValue},
			} {
				t.Run(name, func(t *testing.T) {
					tc.body["schemas"] = []string{string(core.SchemaUser)}
					requireSCIMError(t, c.do(t, http.MethodPost, scimUsersPath, tc.body), http.StatusBadRequest, tc.scimType)
				})
			}
		})
	})

	t.Run("Read", func(t *testing.T) {
		t.Run("GET returns a user", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.get(t, scimUsersPath+"/"+user.ID)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Empty(t, res.Header.Get("ETag"))
			require.Equal(t, user, scimDecode[core.User](t, res))
		})
	})

	t.Run("Replace", func(t *testing.T) {
		t.Run("PUT replaces a user", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPut, scimUsersPath+"/"+user.ID, newSCIMUser(user.UserName, "Babs", "Jensen"))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, core.Name{GivenName: "Babs", FamilyName: "Jensen"}, scimDecode[core.User](t, res).Name)
		})

		t.Run("PUT ignores a stale If-Match because versioning is off", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			req := scimRequest(t, http.MethodPut, scimUsersPath+"/"+user.ID, newSCIMUser(user.UserName, "Babs", "Jensen"))
			req.Header.Set("Authorization", "Bearer "+c.token)
			req.Header.Set("If-Match", `W/"stale"`)
			require.Equal(t, http.StatusOK, c.send(t, req).StatusCode)
		})

		t.Run("PUT rejects an invalid body", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			for name, tc := range map[string]struct {
				body     map[string]any
				scimType scimerrors.ErrorType
			}{
				"active is not a boolean": {map[string]any{"userName": user.UserName, "active": "yes"}, scimerrors.InvalidSyntax},
				"missing userName":        {map[string]any{}, scimerrors.InvalidValue},
			} {
				t.Run(name, func(t *testing.T) {
					tc.body["schemas"] = []string{string(core.SchemaUser)}
					requireSCIMError(t, c.do(t, http.MethodPut, scimUsersPath+"/"+user.ID, tc.body), http.StatusBadRequest, tc.scimType)
				})
			}
		})

		t.Run("PUT ignores the read-only id in the body", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			body := newSCIMUser(user.UserName, "Babs", "Jensen")
			body["id"] = scimMissingID
			res := c.do(t, http.MethodPut, scimUsersPath+"/"+user.ID, body)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, user.ID, scimDecode[core.User](t, res).ID)
			require.Equal(t, "Babs", c.user(t, user.ID).Name.GivenName)
		})
	})

	t.Run("Patch", func(t *testing.T) {
		t.Run("PATCH replaces name.familyName", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "name.familyName", "value": "Jensen-Smith"}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, core.Name{GivenName: "Barbara", FamilyName: "Jensen-Smith"}, scimDecode[core.User](t, res).Name)
		})

		t.Run("PATCH toggles active", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			for _, active := range []bool{false, true} {
				res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "active", "value": active}))
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, &active, scimDecode[core.User](t, res).Active)
			}
		})

		t.Run("PATCH adds, replaces and removes an attribute by path", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			for _, step := range []struct{ op, value string }{{"add", "Babsy"}, {"replace", "Bee"}, {"remove", ""}} {
				operation := map[string]any{"op": step.op, "path": "nickName"}
				if step.op != "remove" {
					operation["value"] = step.value
				}
				res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(operation))
				require.Equal(t, http.StatusOK, res.StatusCode, step.op)
				require.Equal(t, step.value, scimDecode[core.User](t, res).NickName, step.op)
			}
		})

		t.Run("PATCH adds and replaces attributes without a path", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			for _, op := range []string{"add", "replace"} {
				res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": op, "value": map[string]any{"title": "Title " + op}}))
				require.Equal(t, http.StatusOK, res.StatusCode, op)
				got := scimDecode[core.User](t, res)
				require.Equal(t, "Title "+op, got.Title, op)
				require.Equal(t, user.UserName, got.UserName, op)
			}
		})

		t.Run("PATCH remove without a path has no target", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "remove"}))
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.NoTarget)
		})

		t.Run("PATCH adds and removes multi-valued values", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			add := newSCIMPatch(map[string]any{"op": "add", "path": "emails", "value": []map[string]any{{"value": "work@example.com", "type": "work"}}})
			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, add)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Len(t, scimDecode[core.User](t, res).Emails, 2)

			remove := newSCIMPatch(map[string]any{"op": "remove", "path": `emails[type eq "work"]`})
			res = c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, remove)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Len(t, scimDecode[core.User](t, res).Emails, 1)
		})

		t.Run("PATCH is atomic", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(
				map[string]any{"op": "replace", "path": "nickName", "value": "Babsy"},
				map[string]any{"op": "replace", "path": "id", "value": scimMissingID},
			))
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.Mutability)
			require.Equal(t, user, c.user(t, user.ID))
		})

		t.Run("PATCH of a primary email clears the other primary", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "add", "path": "emails", "value": []map[string]any{{"value": "work@example.com", "type": "work", "primary": true}}}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			primaries := []string{}
			for _, email := range c.user(t, user.ID).Emails {
				if email.Primary != nil && *email.Primary {
					primaries = append(primaries, email.Value)
				}
			}
			require.Equal(t, []string{"work@example.com"}, primaries)
		})

		t.Run("PATCH replace adds an unset attribute", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "title", "value": "Tour Guide"}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, "Tour Guide", c.user(t, user.ID).Title)
		})

		t.Run("PATCH replace of a complex attribute keeps the other sub-attributes", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "name", "value": map[string]any{"givenName": "Babs"}}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, core.Name{GivenName: "Babs", FamilyName: "Jensen"}, c.user(t, user.ID).Name)
		})

		t.Run("PATCH replace by value filter updates the match or has no target", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))
			path := scimUsersPath + "/" + user.ID
			replace := newSCIMPatch(map[string]any{"op": "replace", "path": `emails[type eq "work"].value`, "value": "new@example.com"})

			requireSCIMError(t, c.do(t, http.MethodPatch, path, replace), http.StatusBadRequest, scimerrors.NoTarget)
			add := newSCIMPatch(map[string]any{"op": "add", "path": "emails", "value": []map[string]any{{"value": "work@example.com", "type": "work"}}})
			require.Equal(t, http.StatusOK, c.do(t, http.MethodPatch, path, add).StatusCode)
			require.Equal(t, http.StatusOK, c.do(t, http.MethodPatch, path, replace).StatusCode)
			values := []string{}
			for _, email := range c.user(t, user.ID).Emails {
				values = append(values, email.Value)
			}
			require.ElementsMatch(t, []string{user.UserName, "new@example.com"}, values)
		})

		t.Run("PATCH remove of the last value unassigns the attribute", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "remove", "path": `emails[value eq "` + user.UserName + `"]`}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Empty(t, c.user(t, user.ID).Emails)
		})

		t.Run("PATCH remove of the required userName is a mutability error", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "remove", "path": "userName"}))
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.Mutability)
		})

		t.Run("PATCH of an extension attribute adds the extension schema", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "add", "path": scimEnterprise("department"), "value": "Tour Operations"}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.ElementsMatch(t, []core.SchemaURI{core.SchemaUser, core.SchemaEnterpriseUser}, c.user(t, user.ID).Schemas)
		})

		t.Run("PATCH add of an existing value keeps meta.lastModified", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))
			add := newSCIMPatch(map[string]any{"op": "add", "path": "title", "value": "Tour Guide"})

			require.Equal(t, http.StatusOK, c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, add).StatusCode)
			before := c.user(t, user.ID).Meta.LastModified
			require.Equal(t, http.StatusOK, c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, add).StatusCode)
			require.Equal(t, before, c.user(t, user.ID).Meta.LastModified)
		})

		t.Run("PATCH rejects the read-only id", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "id", "value": scimMissingID}))
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.Mutability)
		})

		t.Run("PATCH rejects a body without the PatchOp schema or without operations", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			wrongSchema := map[string]any{"schemas": []string{"x"}, "Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}}}
			requireSCIMError(t, c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, wrongSchema), http.StatusBadRequest, scimerrors.InvalidSyntax)
			requireSCIMError(t, c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch()), http.StatusBadRequest, scimerrors.InvalidSyntax)
		})
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("DELETE removes a user", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+user.ID).StatusCode)
			require.Equal(t, http.StatusNotFound, c.get(t, scimUsersPath+"/"+user.ID).StatusCode)
			filter := `userName eq "` + user.UserName + `"`
			require.Zero(t, scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}}).TotalResults)
		})

		t.Run("DELETE repeats as not found", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+user.ID).StatusCode)
			requireSCIMError(t, c.delete(t, scimUsersPath+"/"+user.ID), http.StatusNotFound, "")
		})
	})

	t.Run("Enterprise manager", func(t *testing.T) {
		t.Run("Read", func(t *testing.T) {
			c := newSCIMClient(t, nil)

			t.Run("returns the stored manager", func(t *testing.T) {
				boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Barbara Jensen"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))

				require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, report))
				require.Equal(t, "Tour Operations", report.EnterpriseUser.Department)
				require.Equal(t, report, c.user(t, report.ID))
			})

			t.Run("keeps the case of the stored value", func(t *testing.T) {
				boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Barbara Jensen"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(strings.ToUpper(boss.ID)))

				require.Equal(t, &core.Manager{Value: strings.ToUpper(boss.ID)}, scimManager(t, report))
			})

			t.Run("keeps a value that is not a uuid", func(t *testing.T) {
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport("jane@example.com"))

				require.Equal(t, &core.Manager{Value: "jane@example.com"}, scimManager(t, report))
			})

			t.Run("keeps a uuid that names nothing", func(t *testing.T) {
				unknown := uuid.NewV7().String()
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(unknown))

				require.Equal(t, &core.Manager{Value: unknown}, scimManager(t, report))
			})

			t.Run("omits the extension without a manager", func(t *testing.T) {
				user := c.createUser(t, scimUserName("bjensen"))

				require.Nil(t, user.EnterpriseUser)
				require.Nil(t, c.user(t, user.ID).EnterpriseUser)
			})

			t.Run("ignores a manager in another tenant", func(t *testing.T) {
				other := newSCIMClient(t, nil)
				boss := scimCreate[core.User](t, other, scimUsersPath, newSCIMBoss("Other Tenant Boss"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))

				require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, report))
			})

			t.Run("honours attribute projection", func(t *testing.T) {
				boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Projected Boss"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))
				enterprise := string(core.SchemaEnterpriseUser)

				list := scimSearch(t, c, scimUsersPath, map[string]any{"filter": `id eq "` + report.ID + `"`, "attributes": []string{"userName"}})
				require.Equal(t, 1, list.TotalResults)
				require.NotContains(t, list.Resources[0], enterprise)

				list = scimSearch(t, c, scimUsersPath, map[string]any{"filter": `id eq "` + report.ID + `"`, "excludedAttributes": []string{enterprise + ":manager"}})
				require.Equal(t, 1, list.TotalResults)
				extension, _ := list.Resources[0][enterprise].(map[string]any)
				require.Equal(t, "Tour Operations", extension["department"])
				require.NotContains(t, extension, "manager")

				list = scimSearch(t, c, scimUsersPath, map[string]any{"filter": `id eq "` + report.ID + `"`, "attributes": []string{enterprise + ":manager.value"}})
				require.Equal(t, 1, list.TotalResults)
				extension, _ = list.Resources[0][enterprise].(map[string]any)
				require.Equal(t, map[string]any{"manager": map[string]any{"value": boss.ID}}, extension)
			})
		})

		t.Run("Write", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			enterprise := string(core.SchemaEnterpriseUser)

			t.Run("PUT replaces the manager", func(t *testing.T) {
				first := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("First Boss"))
				second := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Second Boss"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(first.ID))

				body := newSCIMReport(second.ID)
				body["userName"] = report.UserName
				res := c.do(t, http.MethodPut, scimUsersPath+"/"+report.ID, body)
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, &core.Manager{Value: second.ID}, scimManager(t, scimDecode[core.User](t, res)))
			})

			t.Run("PUT ignores the read-only manager.displayName", func(t *testing.T) {
				boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Real Boss"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))

				body := newSCIMReport(boss.ID)
				body["userName"] = report.UserName
				body[enterprise].(map[string]any)["manager"] = map[string]any{"value": boss.ID, "displayName": "Forged"}
				res := c.do(t, http.MethodPut, scimUsersPath+"/"+report.ID, body)
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, scimDecode[core.User](t, res)))
				require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, c.user(t, report.ID)))
			})

			t.Run("PATCH ignores the read-only manager.displayName", func(t *testing.T) {
				boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Real Boss"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))
				forged := map[string]any{"value": boss.ID, "displayName": "Forged"}

				for _, op := range []map[string]any{
					{"op": "replace", "path": enterprise + ":manager", "value": forged},
					{"op": "replace", "value": map[string]any{enterprise: map[string]any{"manager": forged}}},
				} {
					res := c.do(t, http.MethodPatch, scimUsersPath+"/"+report.ID, newSCIMPatch(op))
					require.Equal(t, http.StatusOK, res.StatusCode)
					require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, scimDecode[core.User](t, res)))
					require.Equal(t, &core.Manager{Value: boss.ID}, scimManager(t, c.user(t, report.ID)))
				}
			})

			t.Run("PATCH replaces manager.value", func(t *testing.T) {
				first := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Patch First"))
				second := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Patch Second"))
				report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(first.ID))

				res := c.do(t, http.MethodPatch, scimUsersPath+"/"+report.ID, newSCIMPatch(map[string]any{"op": "replace", "path": enterprise + ":manager.value", "value": second.ID}))
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, &core.Manager{Value: second.ID}, scimManager(t, scimDecode[core.User](t, res)))
			})

			for _, path := range []string{"manager", "manager.value"} {
				t.Run("PATCH removes the manager through "+path, func(t *testing.T) {
					boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Removed Boss"))
					report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))

					res := c.do(t, http.MethodPatch, scimUsersPath+"/"+report.ID, newSCIMPatch(map[string]any{"op": "remove", "path": enterprise + ":" + path}))
					require.Equal(t, http.StatusOK, res.StatusCode)
					require.Nil(t, scimDecode[core.User](t, res).EnterpriseUser.Manager)
					require.Nil(t, c.user(t, report.ID).EnterpriseUser.Manager)
					require.Equal(t, "Tour Operations", c.user(t, report.ID).EnterpriseUser.Department)
				})
			}
		})

		t.Run("Filters", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Barbara Jensen"))
			report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))
			orphan := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport("jane@example.com"))
			for _, tc := range []struct {
				filter string
				ids    []string
			}{
				{`manager.value eq "` + boss.ID + `"`, []string{report.ID}},
				{`manager.value eq "jane@example.com"`, []string{orphan.ID}},
				{`manager pr`, []string{report.ID, orphan.ID}},
			} {
				t.Run(tc.filter, func(t *testing.T) {
					ids := scimIDs(t, c, scimUsersPath, url.Values{"filter": {scimEnterprise(tc.filter)}})
					require.ElementsMatch(t, tc.ids, ids)
				})
			}
		})
	})
}

// RFC 7643 section 4.2
func TestSCIMGroups(t *testing.T) {
	c := newSCIMClient(t, nil)
	createUser := func(t *testing.T) core.User {
		return c.createUser(t, scimUserName("member"))
	}
	create := func(t *testing.T, members ...core.User) core.Group {
		return c.createGroup(t, "Tour Guides "+uuid.NewV7().String(), members...)
	}
	patch := func(t *testing.T, id string, operation map[string]any) *http.Response {
		return c.do(t, http.MethodPatch, scimGroupsPath+"/"+id, newSCIMPatch(operation))
	}

	t.Run("Create", func(t *testing.T) {
		t.Run("POST creates a group with members", func(t *testing.T) {
			user := createUser(t)
			displayName := "Tour Guides " + uuid.NewV7().String()

			res := c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(displayName, user))
			require.Equal(t, http.StatusCreated, res.StatusCode)
			require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
			group := scimDecode[core.Group](t, res)
			require.NotEmpty(t, group.ID)
			require.Equal(t, displayName, group.DisplayName)
			require.Equal(t, []core.Member{scimMember(user)}, group.Members)
		})

		t.Run("POST stores a repeated member once", func(t *testing.T) {
			user := createUser(t)

			require.Equal(t, []core.Member{scimMember(user)}, scimCreate[core.Group](t, c, scimGroupsPath, newSCIMGroup("Tour Guides "+uuid.NewV7().String(), user, user)).Members)
		})

		t.Run("rejects members that are not live resources of the provider", func(t *testing.T) {
			deleted := createUser(t)
			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+deleted.ID).StatusCode)
			foreign := newSCIMClient(t, nil).createUser(t, scimUserName("foreign"))
			group := create(t)

			for name, value := range map[string]string{"unknown": scimMissingID, "foreign": foreign.ID, "deleted": deleted.ID, "malformed": "bjensen"} {
				members := []core.Member{{Value: value}}
				t.Run("POST "+name, func(t *testing.T) {
					body := newSCIMGroup("Tour Guides " + uuid.NewV7().String())
					body["members"] = members
					res := c.do(t, http.MethodPost, scimGroupsPath, body)
					requireSCIMError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
				})
				t.Run("PATCH "+name, func(t *testing.T) {
					res := c.addMembers(t, group.ID, value)
					requireSCIMError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
				})
			}
			require.Empty(t, c.group(t, group.ID).Members)
		})

		t.Run("POST assigns meta and an id that no user has", func(t *testing.T) {
			user := createUser(t)
			group := create(t)

			require.Equal(t, core.ResourceTypeName("Group"), group.Meta.ResourceType)
			require.Equal(t, group.Meta.Created, group.Meta.LastModified)
			location, err := url.Parse(group.Meta.Location)
			require.NoError(t, err)
			require.Equal(t, group, scimDecode[core.Group](t, c.get(t, location.Path)))
			require.NotEqual(t, user.ID, group.ID)
			requireSCIMError(t, c.get(t, scimGroupsPath+"/"+user.ID), http.StatusNotFound, "")
			requireSCIMError(t, c.get(t, scimUsersPath+"/"+group.ID), http.StatusNotFound, "")
		})

		t.Run("POST creates a minimal group", func(t *testing.T) {
			name := "Minimal " + uuid.NewV7().String()

			group := scimCreate[core.Group](t, c, scimGroupsPath, map[string]any{"schemas": []string{string(core.SchemaGroup)}, "displayName": name})
			require.Equal(t, name, group.DisplayName)
			require.Empty(t, group.Members)
		})

		t.Run("POST creates a group with an externalId", func(t *testing.T) {
			user := createUser(t)
			body := newSCIMGroup("Tour Guides "+uuid.NewV7().String(), user)
			body["externalId"] = uuid.NewV7().String()

			group := scimCreate[core.Group](t, c, scimGroupsPath, body)
			require.Equal(t, body["externalId"], group.ExternalID)
			require.Equal(t, group, c.group(t, group.ID))
		})

		t.Run("POST accepts a repeated displayName", func(t *testing.T) {
			name := "Repeated " + uuid.NewV7().String()

			require.Equal(t, http.StatusCreated, c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(name)).StatusCode)
			require.Equal(t, http.StatusCreated, c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(name)).StatusCode)
		})
	})

	t.Run("Read", func(t *testing.T) {
		t.Run("GET returns a group", func(t *testing.T) {
			group := create(t, createUser(t))

			require.Equal(t, group, c.group(t, group.ID))
		})

		t.Run("GET omits members when excluded", func(t *testing.T) {
			group := create(t, createUser(t))

			list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`id eq "` + group.ID + `"`}, "excludedAttributes": {"members"}})
			require.Len(t, list.Resources, 1)
			require.Empty(t, list.Resources[0].Members)

			res := c.get(t, scimGroupsPath+"/"+group.ID+"?excludedAttributes=members")
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Empty(t, scimDecode[core.Group](t, res).Members)
			res = c.do(t, http.MethodPatch, scimGroupsPath+"/"+group.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "renamed " + group.ID}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			c.requireGroup(t, group.ID, "renamed "+group.ID, group.Members[0].Value)
		})
	})

	t.Run("Replace", func(t *testing.T) {
		t.Run("PUT replaces a group", func(t *testing.T) {
			group := create(t, createUser(t))
			other := createUser(t)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, other))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, []core.Member{scimMember(other)}, scimDecode[core.Group](t, res).Members)
		})

		t.Run("PUT keeps a repeated existing member once", func(t *testing.T) {
			user := createUser(t)
			group := create(t, user)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, user, user))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, []core.Member{scimMember(user)}, c.group(t, group.ID).Members)
		})

		t.Run("PUT rejects a body without displayName", func(t *testing.T) {
			group := create(t)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, map[string]any{"schemas": []string{string(core.SchemaGroup)}})
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
		})

		t.Run("PUT ignores a stale If-Match because versioning is off", func(t *testing.T) {
			group := create(t)

			req := scimRequest(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName))
			req.Header.Set("Authorization", "Bearer "+c.token)
			req.Header.Set("If-Match", `W/"stale"`)
			require.Equal(t, http.StatusOK, c.send(t, req).StatusCode)
		})

		t.Run("PUT accepts a displayName that another group has", func(t *testing.T) {
			group, other := create(t), create(t)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(other.DisplayName))
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
	})

	t.Run("Patch", func(t *testing.T) {
		t.Run("PATCH adds members", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user)

			require.Equal(t, http.StatusNoContent, c.addMembers(t, group.ID, other.ID).StatusCode)
			require.ElementsMatch(t, []core.Member{scimMember(user), scimMember(other)}, c.group(t, group.ID).Members)
			list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`id eq "` + group.ID + `"`}})
			require.ElementsMatch(t, []core.Member{scimMember(user), scimMember(other)}, list.Resources[0].Members)
		})

		t.Run("PATCH removes a member by filter", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user, other)

			require.Equal(t, http.StatusNoContent, patch(t, group.ID, map[string]any{"op": "remove", "path": `members[value eq "` + user.ID + `"]`}).StatusCode)
			require.Equal(t, []core.Member{scimMember(other)}, c.group(t, group.ID).Members)
		})

		t.Run("PATCH replaces displayName", func(t *testing.T) {
			group := create(t)

			res := patch(t, group.ID, map[string]any{"op": "replace", "path": "displayName", "value": "Group B"})
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, "Group B", scimDecode[core.Group](t, res).DisplayName)
			require.Equal(t, "Group B", c.group(t, group.ID).DisplayName)
		})

		t.Run("PATCH returns every member when it changes only displayName", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user, other)

			for _, name := range []string{"Renamed " + uuid.NewV7().String(), group.DisplayName} {
				res := patch(t, group.ID, map[string]any{"op": "replace", "value": map[string]any{"id": group.ID, "displayName": name}})
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.ElementsMatch(t, []core.Member{scimMember(user), scimMember(other)}, scimDecode[core.Group](t, res).Members)
			}
		})

		t.Run("PATCH adds and removes members in one request", func(t *testing.T) {
			kept, removed, added, absent := createUser(t), createUser(t), createUser(t), createUser(t)
			group := create(t, kept, removed)

			res := c.do(t, http.MethodPatch, scimGroupsPath+"/"+group.ID, newSCIMPatch(
				map[string]any{"op": "Add", "path": "members", "value": []core.Member{{Value: added.ID}, {Value: kept.ID}}},
				map[string]any{"op": "Remove", "path": `members[value eq "` + removed.ID + `"]`},
				map[string]any{"op": "remove", "path": `members[value eq "` + absent.ID + `"]`},
			))
			require.Equal(t, http.StatusNoContent, res.StatusCode)
			c.requireGroup(t, group.ID, group.DisplayName, kept.ID, added.ID)
		})

		t.Run("PATCH rejects an unknown op and an unknown path", func(t *testing.T) {
			group := create(t)

			bogus := patch(t, group.ID, map[string]any{"op": "bogus", "path": "displayName", "value": "x"})
			requireSCIMError(t, bogus, http.StatusBadRequest, scimerrors.InvalidSyntax)
			unknown := patch(t, group.ID, map[string]any{"op": "replace", "path": "nope", "value": "x"})
			requireSCIMError(t, unknown, http.StatusBadRequest, scimerrors.InvalidPath)
		})

		t.Run("PATCH removes every member without a filter", func(t *testing.T) {
			group := create(t, createUser(t), createUser(t))

			res := patch(t, group.ID, map[string]any{"op": "remove", "path": "members"})
			require.Less(t, res.StatusCode, http.StatusMultipleChoices)
			require.Empty(t, c.group(t, group.ID).Members)
		})

		t.Run("PATCH replaces members", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user)

			res := patch(t, group.ID, map[string]any{"op": "replace", "path": "members", "value": []core.Member{{Value: other.ID}}})
			require.Less(t, res.StatusCode, http.StatusMultipleChoices)
			c.requireGroup(t, group.ID, group.DisplayName, other.ID)
		})

		t.Run("PATCH rejects a change to the immutable members.value", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user)

			res := patch(t, group.ID, map[string]any{"op": "replace", "path": `members[value eq "` + user.ID + `"].value`, "value": other.ID})
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.Mutability)
			c.requireGroup(t, group.ID, group.DisplayName, user.ID)
		})

		t.Run("PATCH returns 200 when attributes is requested", func(t *testing.T) {
			user := createUser(t)
			group := create(t)

			res := c.do(t, http.MethodPatch, scimGroupsPath+"/"+group.ID+"?attributes=displayName", newSCIMAddMembers(user.ID))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, group.DisplayName, scimDecode[core.Group](t, res).DisplayName)
		})

		t.Run("PATCH adds an attribute without a path", func(t *testing.T) {
			group := create(t, createUser(t))
			externalID := uuid.NewV7().String()

			res := patch(t, group.ID, map[string]any{"op": "add", "value": map[string]any{"externalId": externalID}})
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, externalID, scimDecode[core.Group](t, res).ExternalID)
		})
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("DELETE removes a group", func(t *testing.T) {
			group := create(t)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+group.ID).StatusCode)
			require.Equal(t, http.StatusNotFound, c.get(t, scimGroupsPath+"/"+group.ID).StatusCode)
		})

		t.Run("DELETE of a user removes it from its groups", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user, other)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+user.ID).StatusCode)
			require.Equal(t, []core.Member{scimMember(other)}, c.group(t, group.ID).Members)
		})

		t.Run("DELETE repeats as not found", func(t *testing.T) {
			group := create(t)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+group.ID).StatusCode)
			requireSCIMError(t, c.delete(t, scimGroupsPath+"/"+group.ID), http.StatusNotFound, "")
		})
	})

	t.Run("Nesting", func(t *testing.T) {
		t.Run("nests a group in a group", func(t *testing.T) {
			child := create(t)
			parent := create(t)

			require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)
			members := []core.Member{{Value: child.ID}}
			require.Equal(t, members, c.group(t, parent.ID).Members)
			require.Equal(t, members, scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`id eq "` + parent.ID + `"`}}).Resources[0].Members)
		})

		t.Run("derives only direct user groups", func(t *testing.T) {
			user := createUser(t)
			child := create(t, user)
			parent := create(t)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)
			groups := []core.GroupMembership{
				{Value: child.ID},
			}

			require.Equal(t, groups, c.user(t, user.ID).Groups)
			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Babs"}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, groups, scimDecode[core.User](t, res).Groups)
			list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}})
			require.Equal(t, groups, list.Resources[0].Groups)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+child.ID).StatusCode)
			require.Empty(t, c.user(t, user.ID).Groups)
		})
	})
}

// RFC 7644 sections 3.4 and 3.12
func TestSCIMQuery(t *testing.T) {
	t.Run("Filters", func(t *testing.T) {
		t.Run("Accepted", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			enterprise := string(core.SchemaEnterpriseUser)
			decoy := scimCreate[core.User](t, c, scimUsersPath, map[string]any{"schemas": []string{string(core.SchemaUser)}, "userName": "decoy@example.com"})
			user := scimCreate[core.User](t, c, scimUsersPath, newSCIMFullUser("bjensen@example.com", "701984", decoy.ID))

			body := newSCIMGroup("Decoys", decoy)
			body["externalId"] = "Tour-Guides"
			decoys := scimCreate[core.Group](t, c, scimGroupsPath, body)
			body = newSCIMGroup("Tour Guides", user)
			body["externalId"] = "tour-guides"
			group := scimCreate[core.Group](t, c, scimGroupsPath, body)
			decoy, user = c.user(t, decoy.ID), c.user(t, user.ID)

			for _, tc := range []struct{ path, filter, id string }{
				{scimUsersPath, `id eq "` + user.ID + `"`, user.ID},
				{scimUsersPath, `externalId eq "701984"`, user.ID},
				{scimUsersPath, `not (externalId eq "701984")`, decoy.ID},
				{scimUsersPath, `externalId ne "701984"`, decoy.ID},
				{scimUsersPath, `nickName ne "Babsy"`, decoy.ID},
				{scimUsersPath, `emails.value ne "babs@jensen.org"`, decoy.ID},
				{scimUsersPath, `nickName eq null`, decoy.ID},
				{scimUsersPath, `nickName ne null`, user.ID},
				{scimUsersPath, `meta.created gt "` + decoy.Meta.Created.Format(time.RFC3339Nano) + `"`, user.ID},
				{scimUsersPath, `meta.lastModified gt "` + decoy.Meta.LastModified.Format(time.RFC3339Nano) + `"`, user.ID},
				{scimUsersPath, `meta.created ge "` + user.Meta.Created.Format(time.RFC3339Nano) + `"`, user.ID},
				{scimUsersPath, `meta.created le "` + decoy.Meta.Created.Format(time.RFC3339Nano) + `"`, decoy.ID},
				{scimUsersPath, `userName eq "bjensen@example.com"`, user.ID},
				{scimUsersPath, `userName eq "BJensen@Example.com"`, user.ID},
				{scimUsersPath, `meta.resourceType eq "User" and userName eq "bjensen@example.com"`, user.ID},
				{scimUsersPath, `meta.resourceType ne "User" or id eq "` + user.ID + `"`, user.ID},
				{scimUsersPath, `meta.location eq "` + user.Meta.Location + `"`, user.ID},
				{scimUsersPath, `meta.location ne "` + decoy.Meta.Location + `"`, user.ID},
				{scimUsersPath, `meta.version eq "` + strings.ReplaceAll(user.Meta.Version, `"`, `\"`) + `"`, user.ID},
				{scimUsersPath, `meta.version eq "W/\"1\"" or id eq "` + user.ID + `"`, user.ID},
				{scimUsersPath, `name.formatted eq "Ms. Barbara J Jensen III"`, user.ID},
				{scimUsersPath, `name.familyName eq "Jensen-Smith"`, user.ID},
				{scimUsersPath, `name.givenName eq "Babs"`, user.ID},
				{scimUsersPath, `name.middleName eq "Jane"`, user.ID},
				{scimUsersPath, `name.honorificPrefix eq "Ms."`, user.ID},
				{scimUsersPath, `name.honorificSuffix eq "III"`, user.ID},
				{scimUsersPath, `displayName eq "Babs Jensen"`, user.ID},
				{scimUsersPath, `nickName eq "Babsy"`, user.ID},
				{scimUsersPath, `profileUrl eq "https://login.example.com/bjensen"`, user.ID},
				{scimUsersPath, `title eq "Tour Guide"`, user.ID},
				{scimUsersPath, `userType eq "Employee"`, user.ID},
				{scimUsersPath, `preferredLanguage eq "en-CA"`, user.ID},
				{scimUsersPath, `locale eq "en-CA"`, user.ID},
				{scimUsersPath, `timezone eq "America/Edmonton"`, user.ID},
				{scimUsersPath, `active eq false`, user.ID},
				{scimUsersPath, `emails.value eq "babs@jensen.org"`, user.ID},
				{scimUsersPath, `emails.type eq "home"`, user.ID},
				{scimUsersPath, `emails.primary eq true`, user.ID},
				{scimUsersPath, `emails[type eq "home" and value eq "babs@jensen.org"]`, user.ID},
				{scimUsersPath, `emails[primary eq true and type eq "home"]`, user.ID},
				{scimUsersPath, `phoneNumbers.value eq "555-555-8377"`, user.ID},
				{scimUsersPath, `phoneNumbers.type eq "mobile"`, user.ID},
				{scimUsersPath, `phoneNumbers[primary eq true and type eq "mobile"]`, user.ID},
				{scimUsersPath, `ims.value eq "babsj"`, user.ID},
				{scimUsersPath, `photos.value eq "https://photos.example.com/bjensen.jpg"`, user.ID},
				{scimUsersPath, `addresses.formatted eq "100 Universal City Plaza"`, user.ID},
				{scimUsersPath, `addresses.streetAddress eq "100 Universal City Plaza"`, user.ID},
				{scimUsersPath, `addresses.locality eq "Hollywood"`, user.ID},
				{scimUsersPath, `addresses.region eq "CA"`, user.ID},
				{scimUsersPath, `addresses.postalCode eq "91608"`, user.ID},
				{scimUsersPath, `addresses.country eq "US"`, user.ID},
				{scimUsersPath, `addresses.type eq "home"`, user.ID},
				{scimUsersPath, `addresses.primary eq true`, user.ID},
				{scimUsersPath, `entitlements.value eq "tour-guide-badge"`, user.ID},
				{scimUsersPath, `roles.value eq "guide"`, user.ID},
				{scimUsersPath, `x509Certificates.value eq "dGVzdA=="`, user.ID},
				{scimUsersPath, enterprise + `:employeeNumber eq "701984"`, user.ID},
				{scimUsersPath, enterprise + `:costCenter eq "4130"`, user.ID},
				{scimUsersPath, enterprise + `:organization eq "Universal Studios"`, user.ID},
				{scimUsersPath, enterprise + `:division eq "Theme Park"`, user.ID},
				{scimUsersPath, enterprise + `:department eq "Tour Operations"`, user.ID},
				{scimUsersPath, enterprise + `:manager.value eq "` + decoy.ID + `"`, user.ID},
				{scimGroupsPath, `id eq "` + group.ID + `"`, group.ID},
				{scimGroupsPath, `externalId eq "tour-guides"`, group.ID},
				{scimGroupsPath, `externalId eq "Tour-Guides"`, decoys.ID},
				{scimGroupsPath, `externalId ne "Tour-Guides"`, group.ID},
				{scimGroupsPath, `externalId sw "Tour"`, decoys.ID},
				{scimGroupsPath, `not (externalId eq "Tour-Guides")`, group.ID},
				{scimGroupsPath, `displayName eq "Tour Guides"`, group.ID},
				{scimGroupsPath, `displayName eq "tour guides"`, group.ID},
				{scimGroupsPath, `displayName sw "TOUR"`, group.ID},
				{scimGroupsPath, `meta.resourceType eq "Group" and displayName eq "Tour Guides"`, group.ID},
				{scimGroupsPath, `meta.location eq "` + group.Meta.Location + `"`, group.ID},
				{scimGroupsPath, `members.value eq "` + user.ID + `"`, group.ID},
				{scimGroupsPath, `members[value eq "` + user.ID + `"]`, group.ID},
				{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members.value eq "` + user.ID + `"`, group.ID},
				{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members[value eq "` + user.ID + `"]`, group.ID},
				{scimGroupsPath, `displayName eq "Tour Guides" and members[value eq "` + user.ID + `"]`, group.ID},
				{scimGroupsPath, `externalId eq "tour-guides" and members pr`, group.ID},
				{scimGroupsPath, `not (members[value eq "` + decoy.ID + `"])`, group.ID},
				{scimGroupsPath, `members.value ne "` + decoy.ID + `"`, group.ID},
				{scimUsersPath, `userName sw "BJen"`, user.ID},
				{scimUsersPath, `userName gt "c"`, decoy.ID},
				{scimUsersPath, `not (userName eq "bjensen@example.com")`, decoy.ID},
				{scimUsersPath, `externalId sw "7019"`, user.ID},
				{scimUsersPath, `externalId gt "7"`, user.ID},
				{scimUsersPath, `title pr`, user.ID},
				{scimUsersPath, `not (title eq "Tour Guide")`, decoy.ID},
				{scimUsersPath, `title eq "Tour Guide" and nickName eq "Babsy"`, user.ID},
				{scimUsersPath, `title eq "Nope" or nickName eq "Babsy"`, user.ID},
				{scimUsersPath, `title eq "Tour Guide" and userName eq "bjensen@example.com"`, user.ID},
				{scimUsersPath, `title eq "Nope" or userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `name.honorificPrefix co "s."`, user.ID},
				{scimUsersPath, `name.familyName co "n.s" or id eq "` + decoy.ID + `"`, decoy.ID},
				{scimUsersPath, `emails.value ew "@JENSEN.org"`, user.ID},
				{scimUsersPath, `emails pr`, user.ID},
				{scimUsersPath, `emails[value ne "x"]`, user.ID},
				{scimUsersPath, `emails[type eq "home" and not (display pr)]`, user.ID},
				{scimUsersPath, `id eq null or userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `title co null or userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `id eq "nope" or userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `id ne "nope" and userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `id pr and userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `meta pr and userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `meta.location eq "https://example.org/` + user.ID + `" or userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `meta.version ne "bad" and userName eq "decoy@example.com"`, decoy.ID},
				{scimUsersPath, `meta.version eq "W/\"-300000000000000000\"" or userName eq "decoy@example.com"`, decoy.ID},
			} {
				t.Run(tc.filter, func(t *testing.T) {
					require.Equal(t, []string{tc.id}, scimIDs(t, c, tc.path, url.Values{"filter": {tc.filter}}))
				})
			}

			runRows := func(name string, rows []scimFilterRow) {
				t.Run(name, func(t *testing.T) {
					for _, tc := range rows {
						t.Run(tc.filter, func(t *testing.T) {
							require.ElementsMatch(t, tc.ids, scimIDs(t, c, tc.path, url.Values{"filter": {tc.filter}}))
						})
					}
				})
			}
			stamp := func(at time.Time) string { return at.Format(time.RFC3339Nano) }
			onlyUser, onlyDecoy, both, none := []string{user.ID}, []string{decoy.ID}, []string{user.ID, decoy.ID}, []string{}
			onlyGroup, onlyDecoys, bothGroups := []string{group.ID}, []string{decoys.ID}, []string{group.ID, decoys.ID}

			// RFC 7644 3.4.2.2: comparison operators on string, boolean, dateTime, multi-valued, complex and extension attributes.
			runRows("Operators", []scimFilterRow{
				{scimUsersPath, `userName ne "bjensen@example.com"`, onlyDecoy},
				{scimUsersPath, `userName co "jensen"`, onlyUser},
				{scimUsersPath, `userName ew "jensen@example.com"`, onlyUser},
				{scimUsersPath, `userName ge "decoy@example.com"`, onlyDecoy},
				{scimUsersPath, `userName lt "c"`, onlyUser},
				{scimUsersPath, `userName le "bjensen@example.com"`, onlyUser},
				{scimUsersPath, `userName pr and title pr`, onlyUser},
				{scimUsersPath, `active ne false`, onlyDecoy},
				{scimUsersPath, `active pr and title pr`, onlyUser},
				{scimUsersPath, `meta.created lt "` + stamp(user.Meta.Created) + `"`, onlyDecoy},
				{scimUsersPath, `meta.created eq "` + stamp(decoy.Meta.Created) + `"`, onlyDecoy},
				{scimUsersPath, `meta.created pr and title pr`, onlyUser},
				{scimUsersPath, `meta.lastModified ge "` + stamp(user.Meta.LastModified) + `"`, onlyUser},
				{scimUsersPath, `meta.lastModified lt "` + stamp(user.Meta.LastModified) + `"`, onlyDecoy},
				{scimUsersPath, `meta.lastModified le "` + stamp(decoy.Meta.LastModified) + `"`, onlyDecoy},
				{scimUsersPath, `emails.value co "jensen"`, onlyUser},
				{scimUsersPath, `emails.value sw "babs"`, onlyUser},
				{scimUsersPath, `phoneNumbers.value sw "555"`, onlyUser},
				{scimUsersPath, `phoneNumbers pr`, onlyUser},
				{scimUsersPath, `addresses.country co "S"`, onlyUser},
				{scimUsersPath, `name.familyName ne "Jensen-Smith"`, onlyDecoy},
				{scimUsersPath, `name.familyName co "Smith"`, onlyUser},
				{scimUsersPath, `name.familyName sw "jensen"`, onlyUser},
				{scimUsersPath, `name.familyName ew "smith"`, onlyUser},
				{scimUsersPath, `name.givenName ge "Babs"`, onlyUser},
				{scimUsersPath, `name.givenName lt "Z"`, onlyUser},
				{scimUsersPath, `name.givenName le "Babs"`, onlyUser},
				{scimUsersPath, `name.givenName pr`, onlyUser},
				{scimUsersPath, `name pr`, onlyUser},
				{scimUsersPath, enterprise + `:employeeNumber co "7019"`, onlyUser},
				{scimUsersPath, enterprise + `:employeeNumber sw "70"`, onlyUser},
				{scimUsersPath, enterprise + `:employeeNumber ew "984"`, onlyUser},
				{scimUsersPath, enterprise + `:employeeNumber ne "701984"`, onlyDecoy},
				{scimUsersPath, enterprise + `:employeeNumber gt "700000"`, onlyUser},
				{scimUsersPath, enterprise + `:department pr`, onlyUser},
				{scimGroupsPath, `displayName ne "Decoys"`, onlyGroup},
				{scimGroupsPath, `displayName co "Guides"`, onlyGroup},
				{scimGroupsPath, `displayName ew "oys"`, onlyDecoys},
				{scimGroupsPath, `displayName ew "GUIDES"`, onlyGroup},
				{scimGroupsPath, `displayName gt "e"`, onlyGroup},
				{scimGroupsPath, `displayName ge "tour guides"`, onlyGroup},
				{scimGroupsPath, `displayName lt "e"`, onlyDecoys},
				{scimGroupsPath, `displayName le "decoys"`, onlyDecoys},
				{scimGroupsPath, `displayName pr and externalId sw "Tour"`, onlyDecoys},
				{scimGroupsPath, `externalId co "-Guides"`, onlyDecoys},
				{scimGroupsPath, `externalId ew "guides"`, onlyGroup},
			})

			presence := []scimFilterRow{
				{scimUsersPath, `id pr`, both},
				{scimUsersPath, `userName pr`, both},
				{scimUsersPath, `meta.resourceType pr`, both},
				{scimUsersPath, `meta.created pr`, both},
				{scimUsersPath, `meta.lastModified pr`, both},
				{scimUsersPath, `meta.location pr`, both},
				{scimGroupsPath, `id pr`, bothGroups},
				{scimGroupsPath, `displayName pr`, bothGroups},
				{scimGroupsPath, `members.value pr`, bothGroups},
				{scimGroupsPath, `externalId pr`, bothGroups},
			}
			for _, attribute := range []string{
				"externalId", "name.formatted", "name.familyName", "name.givenName", "name.middleName", "name.honorificPrefix", "name.honorificSuffix",
				"displayName", "nickName", "profileUrl", "title", "userType", "preferredLanguage", "locale", "timezone", "active",
				"emails", "emails.value", "emails.type", "emails.primary", "phoneNumbers.value", "phoneNumbers.type", "phoneNumbers.primary",
				"ims", "ims.value", "ims.type", "photos", "photos.value", "photos.type",
				"addresses", "addresses.formatted", "addresses.streetAddress", "addresses.locality", "addresses.region", "addresses.postalCode", "addresses.country", "addresses.type", "addresses.primary",
				"entitlements", "entitlements.value", "roles", "roles.value", "x509Certificates", "x509Certificates.value",
				enterprise + ":employeeNumber", enterprise + ":costCenter", enterprise + ":organization", enterprise + ":division", enterprise + ":department", enterprise + ":manager", enterprise + ":manager.value",
			} {
				presence = append(presence, scimFilterRow{scimUsersPath, attribute + ` pr`, onlyUser})
			}
			for _, attribute := range []string{"emails.display", "phoneNumbers.display", "ims.display", "photos.display", "entitlements.display", "roles.display", "x509Certificates.display"} {
				presence = append(presence, scimFilterRow{scimUsersPath, attribute + ` pr`, none})
			}
			// RFC 7644 3.4.2.2: pr matches an attribute that has a non-empty value.
			runRows("Presence", presence)

			// RFC 7644 3.4.2.2: every comparison operator on every attribute the full user has and the decoy lacks.
			runRows("Operators on every attribute", scimOperatorRows(scimUsersPath, scimFullUserProbes(decoy.ID), onlyUser, onlyDecoy))

			runRows("Operators on attributes every resource has", []scimFilterRow{
				{scimUsersPath, `id ne "` + user.ID + `"`, onlyDecoy},
				{scimUsersPath, `id gt "` + decoy.ID + `"`, onlyUser},
				{scimUsersPath, `id ge "` + user.ID + `"`, onlyUser},
				{scimUsersPath, `id lt "` + user.ID + `"`, onlyDecoy},
				{scimUsersPath, `id le "` + decoy.ID + `"`, onlyDecoy},
				{scimUsersPath, `meta.resourceType eq "User"`, both},
				{scimUsersPath, `meta.resourceType ne "User"`, none},
				{scimUsersPath, `meta.resourceType gt "A"`, both},
				{scimUsersPath, `meta.resourceType ge "User"`, both},
				{scimUsersPath, `meta.resourceType lt "Z"`, both},
				{scimUsersPath, `meta.resourceType le "User"`, both},
				{scimUsersPath, `meta.location gt "` + decoy.Meta.Location + `"`, onlyUser},
				{scimUsersPath, `meta.location ge "` + user.Meta.Location + `"`, onlyUser},
				{scimUsersPath, `meta.location lt "` + user.Meta.Location + `"`, onlyDecoy},
				{scimUsersPath, `meta.location le "` + decoy.Meta.Location + `"`, onlyDecoy},
				{scimUsersPath, `meta.created ne "` + stamp(user.Meta.Created) + `"`, onlyDecoy},
				{scimUsersPath, `meta.lastModified eq "` + stamp(user.Meta.LastModified) + `"`, onlyUser},
				{scimUsersPath, `meta.lastModified ne "` + stamp(user.Meta.LastModified) + `"`, onlyDecoy},
				{scimUsersPath, `active eq false`, onlyUser},
				{scimUsersPath, `active ne true`, both},
				{scimUsersPath, `emails.primary eq true`, onlyUser},
				{scimUsersPath, `emails.primary ne true`, onlyDecoy},
				{scimUsersPath, `phoneNumbers.primary eq true`, onlyUser},
				{scimUsersPath, `phoneNumbers.primary ne true`, onlyDecoy},
				{scimUsersPath, `addresses.primary eq true`, onlyUser},
				{scimUsersPath, `addresses.primary ne true`, onlyDecoy},
				{scimGroupsPath, `id ne "` + group.ID + `"`, onlyDecoys},
				{scimGroupsPath, `id gt "` + decoys.ID + `"`, onlyGroup},
				{scimGroupsPath, `id ge "` + group.ID + `"`, onlyGroup},
				{scimGroupsPath, `id lt "` + group.ID + `"`, onlyDecoys},
				{scimGroupsPath, `id le "` + decoys.ID + `"`, onlyDecoys},
				{scimGroupsPath, `meta.resourceType eq "Group"`, bothGroups},
				{scimGroupsPath, `meta.resourceType ne "Group"`, none},
				{scimGroupsPath, `meta.created ne "` + stamp(group.Meta.Created) + `"`, onlyDecoys},
				{scimGroupsPath, `meta.lastModified eq "` + stamp(group.Meta.LastModified) + `"`, onlyGroup},
				{scimGroupsPath, `externalId gt "Tour-Guides"`, onlyGroup},
				{scimGroupsPath, `externalId ge "tour-guides"`, onlyGroup},
				{scimGroupsPath, `externalId lt "tour-guides"`, onlyDecoys},
				{scimGroupsPath, `externalId le "Tour-Guides"`, onlyDecoys},
				{scimGroupsPath, `externalId sw "tour"`, onlyGroup},
			})

			// RFC 7644 3.4.2.2: and binds tighter than or, parentheses group, not negates.
			runRows("Logical operators", []scimFilterRow{
				{scimUsersPath, `id eq "` + decoy.ID + `" or id eq "` + user.ID + `" and title pr`, both},
				{scimUsersPath, `(id eq "` + decoy.ID + `" or id eq "` + user.ID + `") and title pr`, onlyUser},
				{scimUsersPath, `not (id eq "` + decoy.ID + `") and not (title eq "nope")`, onlyUser},
				{scimUsersPath, `not (not (title pr))`, onlyUser},
				{scimUsersPath, `title pr or userName pr`, both},
				{scimUsersPath, `title pr and (nickName pr or id eq "` + decoy.ID + `")`, onlyUser},
			})

			// RFC 7644 3.4.2.2: a value path filters the elements of a multi-valued attribute.
			runRows("Value paths", []scimFilterRow{
				{scimUsersPath, `emails[type eq "work"]`, none},
				{scimUsersPath, `emails[type eq "home" or type eq "work"]`, onlyUser},
				{scimUsersPath, `emails[not (type eq "work")]`, onlyUser},
				{scimUsersPath, `emails[value ew "jensen.org" and primary eq true]`, onlyUser},
				{scimUsersPath, `phoneNumbers[type eq "mobile" and value sw "555"]`, onlyUser},
				{scimUsersPath, `addresses[country eq "US" and type eq "home"]`, onlyUser},
			})

			runRows("Null and missing attributes", []scimFilterRow{
				{scimUsersPath, `title eq null`, onlyDecoy},
				{scimUsersPath, `emails.value eq null`, onlyDecoy},
				{scimUsersPath, `name.givenName eq null`, onlyDecoy},
				{scimUsersPath, `title co "x"`, none},
				{scimUsersPath, `nickName sw "x"`, none},
			})

			// RFC 7644 3.4.2.2 and 3.10: operators, attribute names and the schema URN are case insensitive.
			runRows("Case rules", []scimFilterRow{
				{scimUsersPath, `userName EQ "bjensen@example.com"`, onlyUser},
				{scimUsersPath, `USERNAME eq "bjensen@example.com"`, onlyUser},
				{scimUsersPath, string(core.SchemaUser) + `:userName eq "bjensen@example.com"`, onlyUser},
				{scimUsersPath, strings.ToUpper(string(core.SchemaUser)) + `:userName eq "bjensen@example.com"`, onlyUser},
				{scimUsersPath, strings.ToLower(enterprise) + `:employeeNumber eq "701984"`, onlyUser},
				{scimUsersPath, `externalId eq "701984" and userName eq "BJENSEN@example.com"`, onlyUser},
			})

			t.Run("matches groups without members", func(t *testing.T) {
				empty := scimCreate[core.Group](t, c, scimGroupsPath, newSCIMGroup("Empty"))
				require.Equal(t, []string{empty.ID}, scimIDs(t, c, scimGroupsPath, url.Values{"filter": {`not (members pr)`}}))
			})
		})

		t.Run("Fold case like Postgres", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			name := "\u00c9MILE\ua7d2"
			user := scimCreate[core.User](t, c, scimUsersPath, newSCIMUser(name+"@example.com", name, "Zola"))

			for _, filter := range []string{
				`userName eq "` + name + `@example.com"`,
				`userName sw "` + name + `"`,
				`name.givenName eq "` + name + `"`,
				`name.givenName sw "` + name + `"`,
				`name.givenName co "` + name + `"`,
				`emails[value ew "` + name + `@example.com"]`,
			} {
				list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}})
				require.Len(t, list.Resources, 1, filter)
				require.Equal(t, user.ID, list.Resources[0].ID, filter)
			}
		})

		t.Run("Prefix order", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			tag := uuid.NewV7().String()
			b, a, accent, next := c.createUser(t, tag+"-b@example.com").ID, c.createUser(t, tag+"-A@example.com").ID, c.createUser(t, tag+"-pr\u00e9@example.com").ID, c.createUser(t, tag+"-pr\u00ea@example.com").ID

			for _, tc := range []struct {
				query url.Values
				want  []string
			}{
				{url.Values{"filter": {`userName sw "` + tag + `-"`}}, []string{b, a, accent, next}},
				{url.Values{"filter": {`userName sw "` + strings.ToUpper(tag) + `-"`}, "sortBy": {"meta.created"}}, []string{b, a, accent, next}},
				{url.Values{"filter": {`userName sw "` + tag + `-pr\u00e9"`}}, []string{accent}},
				{url.Values{"filter": {`userName sw "` + tag + `-a@example.com"`}}, []string{a}},
			} {
				require.Equal(t, tc.want, scimIDs(t, c, scimUsersPath, tc.query), tc.query.Encode())
			}
		})

		t.Run("Value path matches within one value", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			tag := uuid.NewV7().String()
			body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			body["emails"] = []map[string]any{{"value": "home+" + tag + "@example.com", "type": "home"}, {"value": "work+" + tag + "@example.com", "type": "work"}}
			user := scimCreate[core.User](t, c, scimUsersPath, body)

			require.Empty(t, scimIDs(t, c, scimUsersPath, url.Values{"filter": {`emails[type eq "home" and value eq "work+` + tag + `@example.com"]`}}))
			require.Equal(t, []string{user.ID}, scimIDs(t, c, scimUsersPath, url.Values{"filter": {`emails[type eq "work" and value eq "work+` + tag + `@example.com"]`}}))
		})

		t.Run("Unset primary is false", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			body["emails"] = []map[string]any{{"value": body["userName"]}}
			user := scimCreate[core.User](t, c, scimUsersPath, body)

			require.Equal(t, []string{user.ID}, scimIDs(t, c, scimUsersPath, url.Values{"filter": {`emails.primary eq false`}}))
		})

		t.Run("Rejected", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			missing := scimMissingID
			for _, tc := range []struct {
				path, filter string
				status       int
				scimType     scimerrors.ErrorType
			}{
				{scimUsersPath, `userName eq`, http.StatusBadRequest, ""},
				{scimUsersPath, `userName regex "x"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				// RFC 7644 3.4.2.2: gt, ge, lt and le on a binary attribute SHALL fail.
				{scimUsersPath, `x509Certificates.value gt "a"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `x509Certificates.value ge "a"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `x509Certificates.value lt "a"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `x509Certificates.value le "a"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				// RFC 7644 7.5.2: servers SHOULD respond 403 to a GET filter with sensitive information.
				{scimUsersPath, `password eq "t1meMa$heen"`, http.StatusForbidden, scimerrors.Sensitive},
				// RFC 7643 4.3: manager is single-valued, so scim-go rejects any value path on it.
				{scimUsersPath, scimEnterprise(`manager[value eq "` + missing + `"]`), http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, scimEnterprise(`manager[displayName eq "Barbara Jensen"]`), http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, scimEnterprise(`manager[value eq "` + missing + `" and displayName eq "Barbara Jensen"]`), http.StatusBadRequest, scimerrors.InvalidFilter},
				// RFC 7644 3.4.2.2: ATTRNAME starts with ALPHA, so $ref is not filterable.
				{scimUsersPath, scimEnterprise(`manager.$ref eq "https://example.org/Users/` + missing + `"`), http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, scimEnterprise(`manager.$ref pr`), http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `foo eq "x"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `name.nope eq "x"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `userName eq "a" and`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `(userName pr`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `userName pr)`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `not userName pr`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `userName co`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `emails[value[type eq "x"]]`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active gt true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active co "t"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active ge true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active lt true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active le true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active sw "t"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `active ew "e"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `emails.primary gt true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `emails.primary co "t"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `phoneNumbers.primary gt true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `phoneNumbers.primary co "t"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `addresses.primary gt true`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `addresses.primary co "t"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.created co "2"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.created sw "2"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.created ew "Z"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.lastModified co "2"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.lastModified sw "2"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `meta.lastModified ew "Z"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimUsersPath, `userName eq 5`, http.StatusBadRequest, scimerrors.InvalidValue},
				{scimUsersPath, `active eq "true"`, http.StatusBadRequest, scimerrors.InvalidValue},
				{scimUsersPath, `meta.created eq "x"`, http.StatusBadRequest, scimerrors.InvalidValue},
				{scimGroupsPath, `displayName eq`, http.StatusBadRequest, ""},
				{scimGroupsPath, `members.display eq "x"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimGroupsPath, `members.display pr`, http.StatusBadRequest, ""},
				{scimGroupsPath, `members[display pr]`, http.StatusBadRequest, ""},
			} {
				t.Run(tc.path+"?filter="+tc.filter, func(t *testing.T) {
					res := c.get(t, tc.path+"?"+url.Values{"filter": {tc.filter}}.Encode())
					requireSCIMError(t, res, tc.status, tc.scimType)
				})
			}
		})
	})

	t.Run("Sort", func(t *testing.T) {
		t.Run("nested and multi-valued attributes", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			tag := uuid.NewV7().String()
			create := func(userName, familyName, externalID, other string) string {
				body := newSCIMUser(userName+"+"+tag+"@example.com", "Barbara", familyName)
				body["externalId"] = externalID + tag
				body["emails"] = []map[string]any{{"value": other + "+" + tag + "@example.com"}, {"value": userName + "+" + tag + "@example.com", "primary": true}}
				return scimCreate[core.User](t, c, scimUsersPath, body).ID
			}
			a, b := create("a", "Zulu", "B", "z"), create("b", "Alpha", "a", "c")

			for sortBy, want := range map[string][]string{"userName": {a, b}, "emails.value": {a, b}, "name.familyName": {b, a}, "meta.created": {a, b}, "externalId": {a, b}} {
				require.Equal(t, want, scimIDs(t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}, "sortBy": {sortBy}}), sortBy)
			}
		})

		t.Run("case-insensitive attributes sort without case", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			tag := uuid.NewV7().String()
			upper := c.createUser(t, "B+"+tag+"@example.com").ID
			lower := c.createUser(t, "a+"+tag+"@example.com").ID

			require.Equal(t, []string{lower, upper}, scimIDs(t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}, "sortBy": {"userName"}}))
		})

		t.Run("Rejected", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			for _, tc := range []struct {
				path, sortBy string
				scimType     scimerrors.ErrorType
			}{
				{scimUsersPath, "nope", ""},
			} {
				t.Run(tc.path+"?sortBy="+tc.sortBy, func(t *testing.T) {
					res := c.get(t, tc.path+"?"+url.Values{"sortBy": {tc.sortBy}}.Encode())
					requireSCIMError(t, res, http.StatusBadRequest, tc.scimType)
				})
			}
		})
	})

	t.Run("Paginate", func(t *testing.T) {
		t.Run("Users keep creation order and page by startIndex", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			tag := uuid.NewV7().String()
			second := c.createUser(t, "b+"+tag+"@example.com")
			first := c.createUser(t, "a+"+tag+"@example.com")
			filter := `userName co "` + tag + `"`

			require.Equal(t, []string{second.ID, first.ID}, scimIDs(t, c, scimUsersPath, url.Values{"filter": {filter}}))
			for startIndex, want := range map[string]int{"1": 2, "2": 1, "5": 0} {
				list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}, "startIndex": {startIndex}, "count": {"5"}})
				require.Equal(t, 2, list.TotalResults, startIndex)
				require.Len(t, list.Resources, want, startIndex)
			}
		})
	})

	t.Run("Attributes", func(t *testing.T) {
		t.Run("Users GET returns only the requested attributes", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			user := c.createUser(t, scimUserName("bjensen"))

			for _, query := range []url.Values{{"attributes": {"userName"}}, {"excludedAttributes": {"name"}}} {
				res := c.get(t, scimUsersPath+"/"+user.ID+"?"+query.Encode())
				require.Equal(t, http.StatusOK, res.StatusCode)
				got := scimDecode[core.User](t, res)
				require.Equal(t, user.UserName, got.UserName)
				require.Zero(t, got.Name)
			}
		})

		t.Run("search projects Users and Groups", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			user := c.createUser(t, scimUserName("bjensen"))
			c.createUser(t, scimUserName("jsmith"))
			group := c.createGroup(t, "Tour Guides "+uuid.NewV7().String(), user)

			list := scimSearch(t, c, scimUsersPath, map[string]any{"filter": `userName eq "` + user.UserName + `"`, "attributes": []string{"userName"}})
			require.Equal(t, 1, list.TotalResults)
			require.Equal(t, []map[string]any{{"id": user.ID, "userName": user.UserName, "schemas": []any{string(core.SchemaUser)}}}, list.Resources)

			list = scimSearch(t, c, scimGroupsPath, map[string]any{"filter": `displayName eq "` + group.DisplayName + `"`, "excludedAttributes": []string{"members"}})
			require.Equal(t, 1, list.TotalResults)
			require.Equal(t, group.ID, list.Resources[0]["id"])
			require.NotContains(t, list.Resources[0], "members")
		})

		t.Run("Groups GET returns only the requested attributes", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			group := c.createGroup(t, "Tour Guides "+uuid.NewV7().String(), c.createUser(t, scimUserName("member")))

			res := c.get(t, scimGroupsPath+"/"+group.ID+"?attributes=displayName")
			require.Equal(t, http.StatusOK, res.StatusCode)
			got := scimDecode[core.Group](t, res)
			require.Equal(t, group.DisplayName, got.DisplayName)
			require.Empty(t, got.Members)
		})

		t.Run("excludedAttributes never removes id", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			user := c.createUser(t, scimUserName("bjensen"))

			res := c.get(t, scimUsersPath+"/"+user.ID+"?excludedAttributes=id")
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, user.ID, scimDecode[core.User](t, res).ID)
			list := scimSearch(t, c, scimUsersPath, map[string]any{"filter": `id eq "` + user.ID + `"`, "excludedAttributes": []string{"id"}})
			require.Equal(t, user.ID, list.Resources[0]["id"])
		})

		t.Run("attributes and excludedAttributes are mutually exclusive", func(t *testing.T) {
			c := newSCIMClient(t, nil)

			res := c.get(t, scimUsersPath+"?attributes=userName&excludedAttributes=name")
			requireSCIMError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
		})
	})

	t.Run("Search", func(t *testing.T) {
		c := newSCIMClient(t, nil)
		for _, resource := range scimQueryResources {
			for _, search := range []bool{false, true} {
				name := resource.name + " " + scimTransport(search)

				t.Run(name+" filters by name", func(t *testing.T) {
					tag := uuid.NewV7().String()
					target := resource.nameOf("a", tag)
					id := resource.create(t, c, target)
					resource.create(t, c, resource.nameOf("b", tag))

					ids, total := scimListIDs(t, c, resource.path, url.Values{"filter": {resource.attribute + ` eq "` + target + `"`}}, search)
					require.Equal(t, 1, total)
					require.Equal(t, []string{id}, ids)
				})

				t.Run(name+" sorts and paginates", func(t *testing.T) {
					tag := uuid.NewV7().String()
					resource.create(t, c, resource.nameOf("b", tag))
					first := resource.create(t, c, resource.nameOf("a", tag))
					query := url.Values{"filter": {resource.attribute + ` co "` + tag + `"`}, "sortBy": {resource.attribute}, "sortOrder": {"descending"}, "startIndex": {"2"}, "count": {"1"}}

					ids, total := scimListIDs(t, c, resource.path, query, search)
					require.Equal(t, 2, total)
					require.Equal(t, []string{first}, ids)
				})
			}
		}

		for _, resource := range scimQueryResources {
			for _, search := range []bool{false, true} {
				name := resource.name + " " + scimTransport(search)
				tagged := func(t *testing.T, extra url.Values) (string, string, []string, int) {
					tag := uuid.NewV7().String()
					second := resource.create(t, c, resource.nameOf("b", tag))
					first := resource.create(t, c, resource.nameOf("a", tag))
					query := url.Values{"filter": {resource.attribute + ` co "` + tag + `"`}}
					maps.Copy(query, extra)
					ids, total := scimListIDs(t, c, resource.path, query, search)
					return first, second, ids, total
				}

				t.Run(name+" lists every resource without a filter", func(t *testing.T) {
					own := newSCIMClient(t, nil)
					tag := uuid.NewV7().String()
					first := resource.create(t, own, resource.nameOf("a", tag))
					second := resource.create(t, own, resource.nameOf("b", tag))

					ids, total := scimListIDs(t, own, resource.path, url.Values{}, search)
					require.Equal(t, 2, total)
					require.ElementsMatch(t, []string{first, second}, ids)
				})

				t.Run(name+" sorts ascending by default", func(t *testing.T) {
					first, second, ids, total := tagged(t, url.Values{"sortBy": {resource.attribute}})
					require.Equal(t, 2, total)
					require.Equal(t, []string{first, second}, ids)
				})

				t.Run(name+" sorts ascending when asked", func(t *testing.T) {
					first, second, ids, _ := tagged(t, url.Values{"sortBy": {resource.attribute}, "sortOrder": {"ascending"}})
					require.Equal(t, []string{first, second}, ids)
				})

				// RFC 7644 3.4.2.4: a startIndex value less than 1 is interpreted as 1.
				t.Run(name+" treats a startIndex below 1 as 1", func(t *testing.T) {
					for _, startIndex := range []string{"0", "-5"} {
						first, second, ids, total := tagged(t, url.Values{"sortBy": {resource.attribute}, "startIndex": {startIndex}})
						require.Equal(t, 2, total, startIndex)
						require.Equal(t, []string{first, second}, ids, startIndex)
					}
				})

				// RFC 7644 3.4.2.4: a count of 0 returns only totalResults, a negative count is 0.
				t.Run(name+" returns only the total for a count of 0 or less", func(t *testing.T) {
					for _, count := range []string{"0", "-1"} {
						_, _, ids, total := tagged(t, url.Values{"count": {count}})
						require.Equal(t, 2, total, count)
						require.Empty(t, ids, count)
					}
				})

				t.Run(name+" caps count at the advertised maxResults", func(t *testing.T) {
					own := newSCIMClient(t, nil)
					tag := uuid.NewV7().String()
					for i := range 101 {
						resource.create(t, own, resource.nameOf(strconv.Itoa(i), tag))
					}

					ids, total := scimListIDs(t, own, resource.path, url.Values{"count": {"1000"}}, search)
					require.Equal(t, 101, total)
					require.Len(t, ids, 100)
				})
			}
		}
	})

	t.Run("Errors", func(t *testing.T) {
		c := newSCIMClient(t, nil)
		user := c.createUser(t, scimUserName("bjensen"))

		for _, id := range []string{scimMissingID, "not-a-uuid"} {
			for _, route := range scimItemRoutes(id, id) {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					requireSCIMError(t, c.do(t, route.method, route.path, route.body), http.StatusNotFound, "")
				})
			}
		}

		t.Run("deleted resources are not found", func(t *testing.T) {
			user := c.createUser(t, scimUserName("deleted"))
			group := c.createGroup(t, "Deleted "+uuid.NewV7().String())
			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+user.ID).StatusCode)
			require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+group.ID).StatusCode)

			for _, route := range scimItemRoutes(user.ID, group.ID) {
				requireSCIMError(t, c.do(t, route.method, route.path, route.body), http.StatusNotFound, "")
			}
		})

		t.Run("totalResults is present when nothing matches", func(t *testing.T) {
			res := c.get(t, scimUsersPath+"?"+url.Values{"filter": {`userName eq "` + scimUserName("nobody") + `"`}}.Encode())
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.JSONEq(t, "0", string(scimDecode[map[string]json.RawMessage](t, res)["totalResults"]))
		})

		for _, tc := range []struct {
			name, method, path string
			body               any
			status             int
		}{
			{"POST user without userName", http.MethodPost, scimUsersPath, map[string]any{"schemas": []core.SchemaURI{core.SchemaUser}}, http.StatusBadRequest},
			{"POST group without displayName", http.MethodPost, scimGroupsPath, map[string]any{"schemas": []core.SchemaURI{core.SchemaGroup}}, http.StatusBadRequest},
			{"PATCH unknown op", http.MethodPatch, scimUsersPath + "/" + user.ID, newSCIMPatch(map[string]any{"op": "bogus", "path": "active", "value": false}), http.StatusBadRequest},
			{"PATCH unknown path", http.MethodPatch, scimUsersPath + "/" + user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "nope", "value": "x"}), http.StatusBadRequest},
			{"POST /.search", http.MethodPost, "/scim/v2/.search", map[string]any{}, http.StatusNotImplemented},
			{"POST /Users/.search without the SearchRequest schema", http.MethodPost, scimUsersPath + "/.search", map[string]any{}, http.StatusBadRequest},
			{"POST /Groups/.search without the SearchRequest schema", http.MethodPost, scimGroupsPath + "/.search", map[string]any{}, http.StatusBadRequest},
			{"POST /Users/.search with an invalid filter", http.MethodPost, scimUsersPath + "/.search", map[string]any{"schemas": []core.SchemaURI{protocol.SchemaSearchRequest}, "filter": "userName eq"}, http.StatusBadRequest},
		} {
			t.Run(tc.name, func(t *testing.T) {
				requireSCIMError(t, c.do(t, tc.method, tc.path, tc.body), tc.status, "")
			})
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		c := newSCIMClient(t, nil)
		user := c.createUser(t, scimUserName("bjensen"))
		other := c.createUser(t, scimUserName("jsmith"))

		for _, tc := range []struct {
			name, method, path string
			body               any
		}{
			{"POST duplicate userName", http.MethodPost, scimUsersPath, newSCIMUser(user.UserName, "Barbara", "Jensen")},
			{"POST userName that differs only in case", http.MethodPost, scimUsersPath, newSCIMUser(strings.ToUpper(user.UserName), "Barbara", "Jensen")},
			{"PUT duplicate userName", http.MethodPut, scimUsersPath + "/" + other.ID, newSCIMUser(user.UserName, "John", "Smith")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res := c.do(t, tc.method, tc.path, tc.body)
				requireSCIMError(t, res, http.StatusConflict, scimerrors.Uniqueness)
			})
		}
	})

	t.Run("Duplicate externalId", func(t *testing.T) {
		c := newSCIMClient(t, nil)
		externalID := uuid.NewV7().String()
		user := func(userName string) map[string]any {
			user := newSCIMUser(userName, "Barbara", "Jensen")
			user["externalId"] = externalID
			return user
		}
		group := func(displayName string) map[string]any {
			return map[string]any{"schemas": []string{string(core.SchemaGroup)}, "displayName": displayName, "externalId": externalID}
		}
		// RFC 7643 Section 3.1: the server does not enforce externalId uniqueness.
		for range 2 {
			scimCreate[core.User](t, c, scimUsersPath, user(scimUserName("bjensen")))
			scimCreate[core.Group](t, c, scimGroupsPath, group("Group "+uuid.NewV7().String()))
		}
		filter := url.Values{"filter": {`externalId eq "` + externalID + `"`}}
		require.Equal(t, 2, scimList[core.User](t, c, scimUsersPath, filter).TotalResults)
		require.Equal(t, 2, scimList[core.Group](t, c, scimGroupsPath, filter).TotalResults)
	})
}

func TestSCIMTenancy(t *testing.T) {
	t.Run("Isolation", func(t *testing.T) {
		c, other := newSCIMClient(t, nil), newSCIMClient(t, nil)
		user := c.createUser(t, scimUserName("bjensen"))
		group := c.createGroup(t, "Tour Guides "+uuid.NewV7().String(), user)
		user = c.user(t, user.ID)

		for _, route := range scimItemRoutes(user.ID, group.ID) {
			requireSCIMError(t, other.do(t, route.method, route.path, route.body), http.StatusNotFound, "")
		}
		require.Zero(t, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).TotalResults)
		require.Zero(t, scimList[core.Group](t, other, scimGroupsPath, url.Values{"filter": {`displayName eq "` + group.DisplayName + `"`}}).TotalResults)
		require.Zero(t, scimSearch(t, other, scimUsersPath, map[string]any{"filter": `userName eq "` + user.UserName + `"`}).TotalResults)
		require.Zero(t, scimSearch(t, other, scimGroupsPath, map[string]any{"filter": `displayName eq "` + group.DisplayName + `"`}).TotalResults)
		twin := other.createUser(t, user.UserName)
		require.Equal(t, []core.User{twin}, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).Resources)
		user.Groups = []core.GroupMembership{{Value: group.ID}}
		require.Equal(t, user, c.user(t, user.ID))
		require.Equal(t, group, c.group(t, group.ID))
	})

	t.Run("externalId is scoped to the provider", func(t *testing.T) {
		c, other := newSCIMClient(t, nil), newSCIMClient(t, nil)
		externalID := uuid.NewV7().String()
		create := func(c scimClient) string {
			body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			body["externalId"] = externalID
			return scimCreate[core.User](t, c, scimUsersPath, body).ID
		}
		mine, theirs := create(c), create(other)

		filter := url.Values{"filter": {`externalId eq "` + externalID + `"`}}
		require.Equal(t, []string{mine}, scimIDs(t, c, scimUsersPath, filter))
		require.Equal(t, []string{theirs}, scimIDs(t, other, scimUsersPath, filter))
	})

	t.Run("Okta replay", func(t *testing.T) {
		const (
			oktaGroup   = "e9e30dba-f08f-4109-8486-d5c6a331660a"
			oktaBjensen = "2819c223-7f76-453a-919d-413861904646"
			oktaJsmith  = "c75ad752-64ae-4823-840d-ffa80929976c"
			oktaBabs    = "6c5bb468-14b2-4183-baf2-06d523e03bd3"
		)

		t.Run("user lifecycle", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			want := map[string]struct {
				familyName string
				active     bool
			}{
				"assign new user":           {"Smith", true},
				"edit last name":            {"Jensen", true},
				"unassign":                  {"Jensen", false},
				"reassign (PUT sent twice)": {"Jensen", true},
			}

			scimReplay(t, c, "okta_user_lifecycle.json", oktaBjensen, nil, func(t *testing.T, step, id string) {
				require.Contains(t, want, step)
				user := c.user(t, id)
				require.Equal(t, want[step].familyName, user.Name.FamilyName)
				require.Equal(t, new(want[step].active), user.Active)
				require.Empty(t, user.Password)

				list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName eq "jsmith@example.com"`}})
				require.Equal(t, 1, list.TotalResults)
				require.Len(t, list.Resources, 1)
				require.Equal(t, id, list.Resources[0].ID)
			})
		})

		t.Run("group push", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			bjensen := c.createUser(t, "bjensen@example.com")
			jsmith := c.createUser(t, "jsmith@example.com")
			want := map[string]struct {
				displayName string
				members     []string
				active      bool
			}{
				"push group":                          {"Tour Guides", nil, true},
				"add bjensen (sent twice)":            {"Tour Guides", []string{bjensen.ID}, true},
				"retry: bjensen and jsmith":           {"Tour Guides", []string{bjensen.ID, jsmith.ID}, true},
				"remove bjensen":                      {"Tour Guides", []string{jsmith.ID}, true},
				"remove jsmith":                       {"Tour Guides", nil, true},
				"rename":                              {"Group A", nil, true},
				"re-add bjensen (sent twice)":         {"Group A", []string{bjensen.ID}, true},
				"deactivate bjensen":                  {"Group A", []string{bjensen.ID}, false},
				"reactivate bjensen and reassign app": {"Group A", []string{bjensen.ID}, true},
			}

			scimReplay(t, c, "okta_group_push.json", oktaGroup, map[string]string{oktaBjensen: bjensen.ID, oktaJsmith: jsmith.ID}, func(t *testing.T, step, id string) {
				require.Contains(t, want, step)
				c.requireGroup(t, id, want[step].displayName, want[step].members...)
				user := c.user(t, bjensen.ID)
				require.Equal(t, new(want[step].active), user.Active)
			})
		})

		t.Run("group patch", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			bjensen := c.createUser(t, "bjensen@example.com")
			jsmith := c.createUser(t, "jsmith@example.com")
			babs := c.createUser(t, "babs@jensen.org")
			want := map[string]struct {
				displayName string
				members     []string
			}{
				"push group":    {"Tour Guides", []string{bjensen.ID, jsmith.ID}},
				"remove jsmith": {"Tour Guides", []string{bjensen.ID}},
				"add babs":      {"Tour Guides", []string{bjensen.ID, babs.ID}},
				"rename":        {"Group B", []string{bjensen.ID, babs.ID}},
			}

			scimReplay(t, c, "okta_group_patch.json", oktaGroup, map[string]string{oktaBjensen: bjensen.ID, oktaJsmith: jsmith.ID, oktaBabs: babs.ID}, func(t *testing.T, step, id string) {
				require.Contains(t, want, step)
				c.requireGroup(t, id, want[step].displayName, want[step].members...)
			})
		})
	})
}

type scimClient struct {
	inst     *e2eapi.Instance
	provider *models.SSOProvider
	token    string
}

func newSCIMClient(t *testing.T, tweak func(*conf.GlobalConfiguration)) scimClient {
	inst := newSCIMInstance(t, tweak)
	provider := &models.SSOProvider{}
	require.NoError(t, inst.Conn.Create(provider))
	t.Cleanup(func() { require.NoError(t, inst.Conn.Destroy(provider)) })
	require.NoError(t, models.EnableSCIM(inst.Conn, uuid.UUID(provider.ID)))
	_, token, err := models.CreateSCIMToken(inst.Conn, uuid.UUID(provider.ID), nil)
	require.NoError(t, err)
	return scimClient{inst, provider, token}
}

func newSCIMInstance(t *testing.T, tweak func(*conf.GlobalConfiguration)) *e2eapi.Instance {
	config := e2e.Must(e2e.Config())
	config.SSO.SCIM.Enabled = true
	if tweak != nil {
		tweak(config)
	}
	inst, err := e2eapi.New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inst.Close()) })
	return inst
}

func (c scimClient) as(token string) scimClient {
	c.token = token
	return c
}

func (c scimClient) send(t *testing.T, req *http.Request) *http.Response {
	res, err := c.inst.Do(req)
	require.NoError(t, err)
	return scimKeep(t, res)
}

func (c scimClient) do(t *testing.T, method, path string, body any) *http.Response {
	res, err := c.inst.DoAuth(scimRequest(t, method, path, body), c.token)
	require.NoError(t, err)
	return scimKeep(t, res)
}

func (c scimClient) get(t *testing.T, path string) *http.Response {
	return c.do(t, http.MethodGet, path, nil)
}

func (c scimClient) delete(t *testing.T, path string) *http.Response {
	return c.do(t, http.MethodDelete, path, nil)
}

func (c scimClient) admin(t *testing.T, method, path string, body any) *http.Response {
	req := scimRequest(t, method, path, body)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.inst.DoAdmin(req)
	require.NoError(t, err)
	return scimKeep(t, res)
}

func (c scimClient) user(t *testing.T, id string) core.User {
	res := c.get(t, scimUsersPath+"/"+id)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[core.User](t, res)
}

func (c scimClient) group(t *testing.T, id string) core.Group {
	res := c.get(t, scimGroupsPath+"/"+id)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[core.Group](t, res)
}

func (c scimClient) createUser(t *testing.T, userName string) core.User {
	return scimCreate[core.User](t, c, scimUsersPath, newSCIMUser(userName, "Barbara", "Jensen"))
}

func (c scimClient) createGroup(t *testing.T, displayName string, members ...core.User) core.Group {
	return scimCreate[core.Group](t, c, scimGroupsPath, newSCIMGroup(displayName, members...))
}

func (c scimClient) addMembers(t *testing.T, id string, values ...string) *http.Response {
	return c.do(t, http.MethodPatch, scimGroupsPath+"/"+id, newSCIMAddMembers(values...))
}

func (c scimClient) requireGroup(t *testing.T, id, displayName string, members ...string) {
	group := c.group(t, id)
	require.Equal(t, displayName, group.DisplayName)
	require.ElementsMatch(t, members, scimMemberValues(group.Members))
}

func scimCreate[T any](t *testing.T, c scimClient, path string, body any) T {
	res := c.do(t, http.MethodPost, path, body)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	return scimDecode[T](t, res)
}

func scimList[T any](t *testing.T, c scimClient, path string, query url.Values) protocol.ListResponse[T] {
	res := c.get(t, path+"?"+query.Encode())
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[protocol.ListResponse[T]](t, res)
}

func scimIDs(t *testing.T, c scimClient, path string, query url.Values) []string {
	ids := []string{}
	for _, resource := range scimList[core.Base](t, c, path, query).Resources {
		ids = append(ids, resource.ID)
	}
	return ids
}

func scimSearch(t *testing.T, c scimClient, path string, body map[string]any) protocol.ListResponse[map[string]any] {
	body["schemas"] = []core.SchemaURI{protocol.SchemaSearchRequest}
	res := c.do(t, http.MethodPost, path+"/.search", body)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[protocol.ListResponse[map[string]any]](t, res)
}

func scimListIDs(t *testing.T, c scimClient, path string, query url.Values, search bool) ([]string, int) {
	ids := []string{}
	if !search {
		list := scimList[core.Base](t, c, path, query)
		for _, resource := range list.Resources {
			ids = append(ids, resource.ID)
		}
		return ids, list.TotalResults
	}
	body := map[string]any{}
	for key, values := range query {
		switch key {
		case "startIndex", "count":
			number, err := strconv.Atoi(values[0])
			require.NoError(t, err)
			body[key] = number
		default:
			body[key] = values[0]
		}
	}
	list := scimSearch(t, c, path, body)
	for _, resource := range list.Resources {
		ids = append(ids, resource["id"].(string))
	}
	return ids, list.TotalResults
}

func scimTransport(search bool) string {
	if search {
		return "POST .search"
	}
	return "GET"
}

func scimRequest(t *testing.T, method, path string, body any) *http.Request {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, path, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", protocol.MediaType)
	return req
}

func scimKeep(t *testing.T, res *http.Response) *http.Response {
	t.Cleanup(func() { require.NoError(t, res.Body.Close()) })
	return res
}

func scimBody(t *testing.T, res *http.Response) []byte {
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return body
}

func scimDecode[T any](t *testing.T, res *http.Response) T {
	body := scimBody(t, res)
	var value T
	require.NoError(t, json.Unmarshal(body, &value), string(body))
	return value
}

func scimUserName(prefix string) string {
	return prefix + "+" + uuid.NewV7().String() + "@example.com"
}

func newSCIMUser(userName, givenName, familyName string) map[string]any {
	return map[string]any{
		"schemas":  []string{string(core.SchemaUser)},
		"userName": userName,
		"name":     map[string]any{"givenName": givenName, "familyName": familyName},
		"emails":   []map[string]any{{"value": userName, "primary": true}},
		"active":   true,
	}
}

type scimFilterRow struct {
	path, filter string
	ids          []string
}

func newSCIMFullUser(userName, externalID, managerID string) map[string]any {
	enterprise := string(core.SchemaEnterpriseUser)
	return map[string]any{
		"schemas":           []string{string(core.SchemaUser), enterprise},
		"externalId":        externalID,
		"userName":          userName,
		"name":              map[string]any{"formatted": "Ms. Barbara J Jensen III", "familyName": "Jensen-Smith", "givenName": "Babs", "middleName": "Jane", "honorificPrefix": "Ms.", "honorificSuffix": "III"},
		"displayName":       "Babs Jensen",
		"nickName":          "Babsy",
		"profileUrl":        "https://login.example.com/bjensen",
		"title":             "Tour Guide",
		"userType":          "Employee",
		"preferredLanguage": "en-CA",
		"locale":            "en-CA",
		"timezone":          "America/Edmonton",
		"active":            false,
		"password":          "t1meMa$heen",
		"emails":            []map[string]any{{"value": "babs@jensen.org", "type": "home", "primary": true}},
		"phoneNumbers":      []map[string]any{{"value": "555-555-8377", "type": "mobile", "primary": true}},
		"ims":               []map[string]any{{"value": "babsj", "type": "xmpp"}},
		"photos":            []map[string]any{{"value": "https://photos.example.com/bjensen.jpg", "type": "photo"}},
		"addresses":         []map[string]any{{"formatted": "100 Universal City Plaza", "streetAddress": "100 Universal City Plaza", "locality": "Hollywood", "region": "CA", "postalCode": "91608", "country": "US", "type": "home", "primary": true}},
		"entitlements":      []map[string]any{{"value": "tour-guide-badge"}},
		"roles":             []map[string]any{{"value": "guide"}},
		"x509Certificates":  []map[string]any{{"value": "dGVzdA=="}},
		enterprise:          map[string]any{"employeeNumber": "701984", "costCenter": "4130", "organization": "Universal Studios", "division": "Theme Park", "department": "Tour Operations", "manager": map[string]any{"value": managerID}},
	}
}

type scimProbe struct {
	attribute, value, contains, prefix, suffix, below, above string
}

func scimFullUserProbes(managerID string) []scimProbe {
	enterprise := string(core.SchemaEnterpriseUser) + ":"
	return []scimProbe{
		{"externalId", "701984", "0198", "7019", "984", "1", "9"},
		{"name.formatted", "Ms. Barbara J Jensen III", "Barbara", "Ms.", "III", "A", "Z"},
		{"name.familyName", "Jensen-Smith", "n-S", "Jens", "Smith", "A", "Z"},
		{"name.givenName", "Babs", "ab", "Ba", "bs", "A", "Z"},
		{"name.middleName", "Jane", "an", "Ja", "ne", "A", "Z"},
		{"name.honorificPrefix", "Ms.", "s.", "M", ".", "A", "Z"},
		{"name.honorificSuffix", "III", "II", "I", "II", "A", "Z"},
		{"displayName", "Babs Jensen", "s J", "Babs", "Jensen", "A", "Z"},
		{"nickName", "Babsy", "abs", "Ba", "sy", "A", "Z"},
		{"profileUrl", "https://login.example.com/bjensen", "login", "https://", "bjensen", "a", "z"},
		{"title", "Tour Guide", "r G", "Tour", "Guide", "A", "Z"},
		{"userType", "Employee", "ploy", "Emp", "yee", "A", "Z"},
		{"preferredLanguage", "en-CA", "n-C", "en", "CA", "a", "z"},
		{"locale", "en-CA", "n-C", "en", "CA", "a", "z"},
		{"timezone", "America/Edmonton", "ica/E", "Amer", "ton", "A", "Z"},
		{"emails.value", "babs@jensen.org", "jensen", "babs", ".org", "a", "z"},
		{"emails.type", "home", "om", "ho", "me", "a", "z"},
		{"phoneNumbers.value", "555-555-8377", "5-8", "555", "377", "1", "9"},
		{"phoneNumbers.type", "mobile", "ob", "mo", "ile", "a", "z"},
		{"ims.value", "babsj", "abs", "ba", "sj", "a", "z"},
		{"ims.type", "xmpp", "mp", "xm", "pp", "a", "z"},
		{"photos.value", "https://photos.example.com/bjensen.jpg", "photos", "https", ".jpg", "a", "z"},
		{"photos.type", "photo", "ot", "ph", "to", "a", "z"},
		{"addresses.formatted", "100 Universal City Plaza", "City", "100", "Plaza", "0", "z"},
		{"addresses.streetAddress", "100 Universal City Plaza", "City", "100", "Plaza", "0", "z"},
		{"addresses.locality", "Hollywood", "llyw", "Holly", "wood", "a", "z"},
		{"addresses.region", "CA", "A", "C", "A", "A", "Z"},
		{"addresses.postalCode", "91608", "160", "916", "608", "1", "99"},
		{"addresses.country", "US", "S", "U", "S", "A", "Z"},
		{"addresses.type", "home", "om", "ho", "me", "a", "z"},
		{"entitlements.value", "tour-guide-badge", "guide", "tour", "badge", "a", "z"},
		{"roles.value", "guide", "ui", "gu", "de", "a", "z"},
		{enterprise + "employeeNumber", "701984", "0198", "7019", "984", "1", "9"},
		{enterprise + "costCenter", "4130", "13", "41", "30", "1", "9"},
		{enterprise + "organization", "Universal Studios", "al S", "Univ", "dios", "A", "Z"},
		{enterprise + "division", "Theme Park", "e P", "Theme", "Park", "A", "Z"},
		{enterprise + "department", "Tour Operations", "r O", "Tour", "tions", "A", "Z"},
		{enterprise + "manager.value", managerID, managerID[24:30], managerID[:8], managerID[30:], "0", "g"},
	}
}

func scimOperatorRows(path string, probes []scimProbe, present, absent []string) []scimFilterRow {
	rows := []scimFilterRow{}
	for _, probe := range probes {
		quote := func(value string) string { return `"` + value + `"` }
		rows = append(rows,
			scimFilterRow{path, probe.attribute + ` eq ` + quote(probe.value), present},
			scimFilterRow{path, probe.attribute + ` ne ` + quote(probe.value), absent},
			scimFilterRow{path, probe.attribute + ` co ` + quote(probe.contains), present},
			scimFilterRow{path, probe.attribute + ` sw ` + quote(probe.prefix), present},
			scimFilterRow{path, probe.attribute + ` ew ` + quote(probe.suffix), present},
			scimFilterRow{path, probe.attribute + ` gt ` + quote(probe.below), present},
			scimFilterRow{path, probe.attribute + ` ge ` + quote(probe.value), present},
			scimFilterRow{path, probe.attribute + ` lt ` + quote(probe.above), present},
			scimFilterRow{path, probe.attribute + ` le ` + quote(probe.value), present},
			scimFilterRow{path, probe.attribute + ` pr`, present},
		)
	}
	return rows
}

func newSCIMGroup(displayName string, members ...core.User) map[string]any {
	values := []core.Member{}
	for _, member := range members {
		values = append(values, core.Member{Value: member.ID})
	}
	return map[string]any{
		"schemas":     []string{string(core.SchemaGroup)},
		"displayName": displayName,
		"members":     values,
	}
}

func scimMember(user core.User) core.Member {
	return core.Member{Value: user.ID}
}

func newSCIMPatch(operations ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{string(protocol.SchemaPatchOp)},
		"Operations": operations,
	}
}

func newSCIMAddMembers(values ...string) map[string]any {
	members := make([]core.Member, len(values))
	for i, value := range values {
		members[i] = core.Member{Value: value}
	}
	return newSCIMPatch(map[string]any{"op": "add", "path": "members", "value": members})
}

func scimEnterprise(filter string) string {
	return string(core.SchemaEnterpriseUser) + ":" + filter
}

func newSCIMBoss(displayName string) map[string]any {
	body := newSCIMUser(scimUserName("boss"), "Barbara", "Jensen")
	if displayName != "" {
		body["displayName"] = displayName
	}
	return body
}

func newSCIMReport(manager string) map[string]any {
	body := newSCIMUser(scimUserName("report"), "Babs", "Jensen")
	body["schemas"] = []string{string(core.SchemaUser), string(core.SchemaEnterpriseUser)}
	body[string(core.SchemaEnterpriseUser)] = map[string]any{
		"department": "Tour Operations",
		"manager":    map[string]any{"value": manager},
	}
	return body
}

type scimRoute struct {
	method, path string
	body         any
}

func scimItemRoutes(userID, groupID string) []scimRoute {
	user, group := scimUsersPath+"/"+userID, scimGroupsPath+"/"+groupID
	deactivate := newSCIMPatch(map[string]any{"op": "replace", "path": "active", "value": false})
	rename := newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Group B"})
	return []scimRoute{
		{http.MethodGet, user, nil},
		{http.MethodPut, user, newSCIMUser(scimUserName("jsmith"), "John", "Smith")},
		{http.MethodPatch, user, deactivate},
		{http.MethodDelete, user, nil},
		{http.MethodGet, group, nil},
		{http.MethodPut, group, newSCIMGroup("Group B")},
		{http.MethodPatch, group, rename},
		{http.MethodDelete, group, nil},
	}
}

var scimQueryResources = []struct {
	name, path, attribute string
	nameOf                func(prefix, tag string) string
	create                func(t *testing.T, c scimClient, name string) string
}{
	{
		"Users", scimUsersPath, "userName",
		func(prefix, tag string) string { return prefix + "+" + tag + "@example.com" },
		func(t *testing.T, c scimClient, name string) string { return c.createUser(t, name).ID },
	},
	{
		"Groups", scimGroupsPath, "displayName",
		func(prefix, tag string) string { return prefix + " " + tag },
		func(t *testing.T, c scimClient, name string) string { return c.createGroup(t, name).ID },
	},
}

func requireSCIMError(t *testing.T, res *http.Response, status int, scimType scimerrors.ErrorType) scimerrors.Error {
	require.Equal(t, status, res.StatusCode)
	require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
	body := scimDecode[scimerrors.Error](t, res)
	require.Contains(t, body.Schemas, protocol.SchemaError)
	if scimType != "" {
		require.Equal(t, scimType, body.ScimType)
	}
	return body
}

func scimManager(t *testing.T, user core.User) *core.Manager {
	t.Helper()
	require.NotNil(t, user.EnterpriseUser)
	require.NotNil(t, user.EnterpriseUser.Manager)
	return user.EnterpriseUser.Manager
}

func scimMemberValues(members []core.Member) []string {
	values := []string{}
	for _, member := range members {
		values = append(values, member.Value)
	}
	return values
}

func scimFixture(t *testing.T, name string) []byte {
	root, err := os.OpenRoot("testdata/scim")
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	raw, err := root.ReadFile(name)
	require.NoError(t, err)
	return raw
}

func scimReplay(t *testing.T, c scimClient, file, created string, ids map[string]string, check func(t *testing.T, step, id string)) {
	raw := scimFixture(t, file)
	var steps []struct {
		Step     string `json:"step"`
		Requests []struct {
			Method string          `json:"method"`
			Path   string          `json:"path"`
			Body   json.RawMessage `json:"body"`
		} `json:"requests"`
	}
	pairs := []string{}
	for from, to := range ids {
		pairs = append(pairs, from, to)
	}
	require.NoError(t, json.Unmarshal([]byte(strings.NewReplacer(pairs...).Replace(string(raw))), &steps))
	require.NotEmpty(t, steps)

	id := created
	for _, step := range steps {
		t.Run(step.Step, func(t *testing.T) {
			for _, request := range step.Requests {
				var body any
				if len(request.Body) > 0 && string(request.Body) != "null" {
					body = json.RawMessage(strings.ReplaceAll(string(request.Body), created, id))
				}
				path := strings.ReplaceAll(request.Path, created, id)
				res := c.do(t, request.Method, path, body)
				got := scimBody(t, res)
				require.Less(t, res.StatusCode, 300, "%s %s: %s", request.Method, path, got)
				if request.Method == http.MethodPost {
					var resource core.Base
					require.NoError(t, json.Unmarshal(got, &resource))
					id = resource.ID
				}
			}
			check(t, step.Step, id)
		})
	}
}
