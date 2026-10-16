package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/scimtest"
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

func TestSCIMSuite(t *testing.T) {
	c := newSCIMClient(t, nil)
	scimtest.NewSuite(scimtest.NewClient(
		c.inst.APIServer.URL+"/scim/v2",
		scimtest.WithHTTPClient(c.inst.APIClient),
		scimtest.WithBearerToken(c.token),
	), scimtest.Strict()).Run(t)
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
			return scimtest.Decode[api.AdminSCIMStatusResponse](t, res)
		}
		create := func(t *testing.T, body any) api.AdminSCIMTokenCreateResponse {
			res := c.admin(t, http.MethodPost, tokensPath, body)
			require.Equal(t, http.StatusCreated, res.StatusCode)
			return scimtest.Decode[api.AdminSCIMTokenCreateResponse](t, res)
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

		t.Run("DELETE token revokes once and repeats safely", func(t *testing.T) {
			token := create(t, nil)
			first := revoke(t, token.ID.String())
			require.Equal(t, http.StatusOK, first.StatusCode)
			revoked := scimtest.Decode[models.SCIMToken](t, first)
			require.NotNil(t, revoked.RevokedAt)

			second := revoke(t, token.ID.String())
			require.Equal(t, http.StatusOK, second.StatusCode)
			require.Equal(t, revoked, scimtest.Decode[models.SCIMToken](t, second))

			require.Equal(t, http.StatusUnauthorized, c.as(token.Token).get(t, scimUsersPath).StatusCode)
			require.NotContains(t, status(t, http.MethodGet).Tokens, revoked)

			res := c.admin(t, http.MethodGet, tokensPath, nil)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Contains(t, scimtest.Decode[api.AdminSCIMTokenListResponse](t, res).Tokens, revoked)
		})

		t.Run("DELETE token returns 404 for a token it cannot find", func(t *testing.T) {
			other := newSCIMClient(t, nil)
			foreign, _, err := models.CreateSCIMToken(other.inst.Conn, uuid.UUID(other.provider.ID), nil)
			require.NoError(t, err)

			want := string(scimBody(t, revoke(t, "not-a-uuid")))
			require.Contains(t, want, `"error_code":"sso_provider_not_found"`)
			for _, id := range []string{uuid.NewV7().String(), foreign.ID.String()} {
				res := revoke(t, id)
				require.Equal(t, http.StatusNotFound, res.StatusCode, id)
				require.Equal(t, want, string(scimBody(t, res)), id)
			}
		})
	})
}

// RFC 7644 sections 3.1 to 3.6, RFC 7643 sections 4.1 and 4.3
func TestSCIMUsers(t *testing.T) {
	c := newSCIMClient(t, nil)

	// RFC 7643 Section 4.1.1: if a service provider holds the password locally, it SHOULD be hashed.
	t.Run("never stores the password", func(t *testing.T) {
		password := "t1meMa$heen"
		body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
		body["password"] = password
		user := scimCreate[core.User](t, c, scimUsersPath, body)
		stored := func(t *testing.T) string {
			var row struct {
				Resource string `db:"resource"`
			}
			require.NoError(t, c.inst.Conn.RawQuery("SELECT resource::text AS resource FROM scim_resources WHERE id = ?", user.ID).First(&row))
			return row.Resource
		}

		require.NotContains(t, stored(t), password)
		require.Equal(t, http.StatusOK, c.do(t, http.MethodPut, scimUsersPath+"/"+user.ID, body).StatusCode)
		require.NotContains(t, stored(t), password)
		require.Equal(t, http.StatusOK, c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "password", "value": password})).StatusCode)
		require.NotContains(t, stored(t), password)
	})

	t.Run("Patch", func(t *testing.T) {
		t.Run("PATCH toggles active", func(t *testing.T) {
			user := c.createUser(t, scimUserName("bjensen"))

			for _, active := range []bool{false, true} {
				res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "active", "value": active}))
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, &active, scimtest.Decode[core.User](t, res).Active)
			}
		})
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("DELETE drops the manager and bumps linked versions", func(t *testing.T) {
			boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Leaving Boss"))
			report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))
			group := c.createGroup(t, "Bosses "+uuid.NewV7().String(), boss)
			require.NotEqual(t, boss.Meta.Version, c.user(t, boss.ID).Meta.Version)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+boss.ID).StatusCode)
			after := c.user(t, report.ID)
			require.Nil(t, after.EnterpriseUser.Manager)
			require.Equal(t, "Tour Operations", after.EnterpriseUser.Department)
			require.NotEqual(t, report.Meta.Version, after.Meta.Version)
			require.NotEqual(t, group.Meta.Version, c.group(t, group.ID).Meta.Version)
		})
	})

	t.Run("Enterprise manager", func(t *testing.T) {
		t.Run("Read", func(t *testing.T) {
			c := newSCIMClient(t, nil)

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
		})

		t.Run("Filters", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			orphan := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport("jane@example.com"))

			ids := scimIDs(t, c, scimUsersPath, url.Values{"filter": {scimEnterprise(`manager.value eq "jane@example.com"`)}})
			require.Equal(t, []string{orphan.ID}, ids)
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
					scimtest.RequireError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
				})
				t.Run("PATCH "+name, func(t *testing.T) {
					res := c.addMembers(t, group.ID, value)
					scimtest.RequireError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
				})
			}
			require.Empty(t, c.group(t, group.ID).Members)
		})

		t.Run("POST accepts a repeated displayName", func(t *testing.T) {
			name := "Repeated " + uuid.NewV7().String()

			require.Equal(t, http.StatusCreated, c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(name)).StatusCode)
			require.Equal(t, http.StatusCreated, c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(name)).StatusCode)
		})
	})

	t.Run("Read", func(t *testing.T) {
		t.Run("GET omits members when excluded", func(t *testing.T) {
			group := create(t, createUser(t))

			list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`id eq "` + group.ID + `"`}, "excludedAttributes": {"members"}})
			require.Len(t, list.Resources, 1)
			require.Empty(t, list.Resources[0].Members)

			res := c.get(t, scimGroupsPath+"/"+group.ID+"?excludedAttributes=members")
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Empty(t, scimtest.Decode[core.Group](t, res).Members)
			res = c.do(t, http.MethodPatch, scimGroupsPath+"/"+group.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "renamed " + group.ID}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			c.requireGroup(t, group.ID, "renamed "+group.ID, group.Members[0].Value)
		})
	})

	t.Run("Replace", func(t *testing.T) {
		t.Run("PUT keeps a repeated existing member once", func(t *testing.T) {
			user := createUser(t)
			group := create(t, user)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, user, user))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, []core.Member{scimMember(user)}, c.group(t, group.ID).Members)
		})

		t.Run("PUT accepts a displayName that another group has", func(t *testing.T) {
			group, other := create(t), create(t)

			res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(other.DisplayName))
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
	})

	t.Run("Patch", func(t *testing.T) {
		t.Run("PATCH returns every member when it changes only displayName", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user, other)

			for _, name := range []string{"Renamed " + uuid.NewV7().String(), group.DisplayName} {
				res := patch(t, group.ID, map[string]any{"op": "replace", "value": map[string]any{"id": group.ID, "displayName": name}})
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.ElementsMatch(t, []core.Member{scimMember(user), scimMember(other)}, scimtest.Decode[core.Group](t, res).Members)
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
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("a soft delete outside the API removes its links", func(t *testing.T) {
			user, other := createUser(t), createUser(t)
			group := create(t, user, other)
			softDelete := func(id string) {
				require.NoError(t, c.inst.Conn.RawQuery("UPDATE scim_resources SET deleted_at = now() WHERE id = ?", id).Exec())
			}

			softDelete(other.ID)
			require.Equal(t, []core.Member{scimMember(user)}, c.group(t, group.ID).Members)

			softDelete(group.ID)
			require.Empty(t, c.user(t, user.ID).Groups)
		})
	})

	t.Run("Nesting", func(t *testing.T) {
		t.Run("rejects a cycle", func(t *testing.T) {
			top, middle, bottom := create(t), create(t), create(t)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, top.ID, middle.ID).StatusCode)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, middle.ID, bottom.ID).StatusCode)

			for _, id := range []string{top.ID, middle.ID, bottom.ID} {
				scimtest.RequireError(t, c.addMembers(t, bottom.ID, id), http.StatusBadRequest, scimerrors.InvalidValue)
			}
			require.Empty(t, c.group(t, bottom.ID).Members)
		})

		t.Run("derives direct and indirect user groups", func(t *testing.T) {
			user := createUser(t)
			child := create(t, user)
			parent := create(t)
			grandparent := create(t)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, grandparent.ID, parent.ID).StatusCode)
			groups := []core.GroupMembership{
				{Value: child.ID, Type: "direct"},
				{Value: parent.ID, Type: "indirect"},
				{Value: grandparent.ID, Type: "indirect"},
			}

			require.ElementsMatch(t, groups, c.user(t, user.ID).Groups)
			res := c.do(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Babs"}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.ElementsMatch(t, groups, scimtest.Decode[core.User](t, res).Groups)
			list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}})
			require.ElementsMatch(t, groups, list.Resources[0].Groups)

			require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+child.ID).StatusCode)
			require.Empty(t, c.user(t, user.ID).Groups)
		})

		t.Run("lists a group once as direct when it is also indirect", func(t *testing.T) {
			user := createUser(t)
			child := create(t, user)
			parent := create(t, user)
			require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)

			require.ElementsMatch(t, []core.GroupMembership{
				{Value: child.ID, Type: "direct"},
				{Value: parent.ID, Type: "direct"},
			}, c.user(t, user.ID).Groups)
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
				{scimUsersPath, `not (externalId eq "701984")`, decoy.ID},
				{scimUsersPath, `externalId ne "701984"`, decoy.ID},
				{scimUsersPath, `nickName ne "Babsy"`, decoy.ID},
				{scimUsersPath, `emails.value ne "babs@jensen.org"`, decoy.ID},
				{scimUsersPath, `meta.resourceType ne "User" or id eq "` + user.ID + `"`, user.ID},
				{scimUsersPath, `meta.location eq "` + user.Meta.Location + `"`, user.ID},
				{scimUsersPath, `meta.location ne "` + decoy.Meta.Location + `"`, user.ID},
				{scimUsersPath, `meta.version eq "` + strings.ReplaceAll(user.Meta.Version, `"`, `\"`) + `"`, user.ID},
				{scimUsersPath, `meta.version eq "W/\"1\"" or id eq "` + user.ID + `"`, user.ID},
				{scimUsersPath, `emails[type eq "home" and value eq "babs@jensen.org"]`, user.ID},
				{scimUsersPath, `emails[primary eq true and type eq "home"]`, user.ID},
				{scimUsersPath, `phoneNumbers[primary eq true and type eq "mobile"]`, user.ID},
				{scimUsersPath, enterprise + `:manager.value eq "` + decoy.ID + `"`, user.ID},
				{scimGroupsPath, `externalId eq "tour-guides"`, group.ID},
				{scimGroupsPath, `externalId eq "Tour-Guides"`, decoys.ID},
				{scimGroupsPath, `externalId ne "Tour-Guides"`, group.ID},
				{scimGroupsPath, `externalId sw "Tour"`, decoys.ID},
				{scimGroupsPath, `not (externalId eq "Tour-Guides")`, group.ID},
				{scimGroupsPath, `displayName sw "TOUR"`, group.ID},
				{scimGroupsPath, `meta.resourceType eq "Group" and displayName eq "Tour Guides"`, group.ID},
				{scimGroupsPath, `meta.location eq "` + group.Meta.Location + `"`, group.ID},
				{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members.value eq "` + user.ID + `"`, group.ID},
				{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members[value eq "` + user.ID + `"]`, group.ID},
				{scimGroupsPath, `displayName eq "Tour Guides" and members[value eq "` + user.ID + `"]`, group.ID},
				{scimGroupsPath, `externalId eq "tour-guides" and members pr`, group.ID},
				{scimGroupsPath, `members.value ne "` + decoy.ID + `"`, group.ID},
				{scimUsersPath, `userName sw "BJen"`, user.ID},
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
			onlyUser, onlyDecoy, both, none := []string{user.ID}, []string{decoy.ID}, []string{user.ID, decoy.ID}, []string{}
			onlyGroup, onlyDecoys := []string{group.ID}, []string{decoys.ID}

			// RFC 7644 3.4.2.2: comparison operators on string, boolean, dateTime, multi-valued, complex and extension attributes.
			runRows("Operators", []scimFilterRow{
				{scimUsersPath, `not (title co "tour")`, onlyDecoy},
				{scimUsersPath, `userName pr and title pr`, onlyUser},
				{scimUsersPath, `active ne false`, onlyDecoy},
				{scimUsersPath, `active pr and title pr`, onlyUser},
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
				{scimGroupsPath, `displayName ew "GUIDES"`, onlyGroup},
				{scimGroupsPath, `displayName gt "e"`, onlyGroup},
				{scimGroupsPath, `displayName ge "tour guides"`, onlyGroup},
				{scimGroupsPath, `displayName lt "e"`, onlyDecoys},
				{scimGroupsPath, `displayName le "decoys"`, onlyDecoys},
				{scimGroupsPath, `displayName pr and externalId sw "Tour"`, onlyDecoys},
				{scimGroupsPath, `externalId co "-Guides"`, onlyDecoys},
				{scimGroupsPath, `externalId ew "guides"`, onlyGroup},
			})

			runRows("Operators on attributes every resource has", []scimFilterRow{
				{scimUsersPath, `id ne "` + user.ID + `"`, onlyDecoy},
				{scimUsersPath, `id gt "` + decoy.ID + `"`, onlyUser},
				{scimUsersPath, `id ge "` + user.ID + `"`, onlyUser},
				{scimUsersPath, `id lt "` + user.ID + `"`, onlyDecoy},
				{scimUsersPath, `id le "` + decoy.ID + `"`, onlyDecoy},
				{scimUsersPath, `meta.resourceType gt "A"`, both},
				{scimUsersPath, `meta.resourceType ge "User"`, both},
				{scimUsersPath, `meta.resourceType lt "Z"`, both},
				{scimUsersPath, `meta.resourceType le "User"`, both},
				{scimUsersPath, `meta.location gt "` + decoy.Meta.Location + `"`, onlyUser},
				{scimUsersPath, `meta.location ge "` + user.Meta.Location + `"`, onlyUser},
				{scimUsersPath, `meta.location lt "` + user.Meta.Location + `"`, onlyDecoy},
				{scimUsersPath, `meta.location le "` + decoy.Meta.Location + `"`, onlyDecoy},
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
				{scimGroupsPath, `externalId gt "Tour-Guides"`, onlyGroup},
				{scimGroupsPath, `externalId ge "tour-guides"`, onlyGroup},
				{scimGroupsPath, `externalId lt "tour-guides"`, onlyDecoys},
				{scimGroupsPath, `externalId le "Tour-Guides"`, onlyDecoys},
				{scimGroupsPath, `externalId sw "tour"`, onlyGroup},
			})

			// RFC 7644 3.4.2.2: and binds tighter than or, parentheses group, not negates.
			runRows("Logical operators", []scimFilterRow{
				{scimUsersPath, `not (not (title pr))`, onlyUser},
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
				{scimUsersPath, `emails.value eq null`, onlyDecoy},
				{scimUsersPath, `name.givenName eq null`, onlyDecoy},
				{scimUsersPath, `title co "x"`, none},
				{scimUsersPath, `nickName sw "x"`, none},
			})

			// RFC 7644 3.4.2.2 and 3.10: operators, attribute names and the schema URN are case insensitive.
			runRows("Case rules", []scimFilterRow{
				{scimUsersPath, strings.ToLower(enterprise) + `:employeeNumber eq "701984"`, onlyUser},
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

		t.Run("Rejected", func(t *testing.T) {
			c := newSCIMClient(t, nil)
			for _, tc := range []struct {
				path, filter string
				status       int
				scimType     scimerrors.ErrorType
			}{
				{scimGroupsPath, `members.display eq "x"`, http.StatusBadRequest, scimerrors.InvalidFilter},
				{scimGroupsPath, `members.display pr`, http.StatusBadRequest, ""},
				{scimGroupsPath, `members[display pr]`, http.StatusBadRequest, ""},
			} {
				t.Run(tc.path+"?filter="+tc.filter, func(t *testing.T) {
					res := c.get(t, tc.path+"?"+url.Values{"filter": {tc.filter}}.Encode())
					scimtest.RequireError(t, res, tc.status, tc.scimType)
				})
			}
		})
	})

	t.Run("Errors", func(t *testing.T) {
		c := newSCIMClient(t, nil)

		for _, id := range []string{scimMissingID, "not-a-uuid"} {
			for _, route := range scimItemRoutes(id, id) {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					scimtest.RequireError(t, c.do(t, route.method, route.path, route.body), http.StatusNotFound, "")
				})
			}
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
			scimtest.RequireError(t, other.do(t, route.method, route.path, route.body), http.StatusNotFound, "")
		}
		require.Zero(t, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).TotalResults)
		require.Zero(t, scimList[core.Group](t, other, scimGroupsPath, url.Values{"filter": {`displayName eq "` + group.DisplayName + `"`}}).TotalResults)
		require.Zero(t, scimSearch(t, other, scimUsersPath, map[string]any{"filter": `userName eq "` + user.UserName + `"`}).TotalResults)
		require.Zero(t, scimSearch(t, other, scimGroupsPath, map[string]any{"filter": `displayName eq "` + group.DisplayName + `"`}).TotalResults)
		twin := other.createUser(t, user.UserName)
		require.Equal(t, []core.User{twin}, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).Resources)
		user.Groups = []core.GroupMembership{{Value: group.ID, Type: "direct"}}
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
	api      *scimtest.Client
}

func newSCIMClient(t *testing.T, tweak func(*conf.GlobalConfiguration)) scimClient {
	inst := newSCIMInstance(t, tweak)
	provider := &models.SSOProvider{}
	require.NoError(t, inst.Conn.Create(provider))
	t.Cleanup(func() { require.NoError(t, inst.Conn.Destroy(provider)) })
	require.NoError(t, models.EnableSCIM(inst.Conn, uuid.UUID(provider.ID)))
	_, token, err := models.CreateSCIMToken(inst.Conn, uuid.UUID(provider.ID), nil)
	require.NoError(t, err)
	return scimClient{inst, provider, token, scimtest.NewClient(inst.APIServer.URL, scimtest.WithHTTPClient(inst.APIClient), scimtest.WithBearerToken(token))}
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
	c.api = c.api.With(scimtest.WithBearerToken(token))
	return c
}

func (c scimClient) send(t *testing.T, req *http.Request) *http.Response {
	res, err := c.inst.Do(req)
	require.NoError(t, err)
	return scimKeep(t, res)
}

func (c scimClient) do(t *testing.T, method, path string, body any) *http.Response {
	return c.api.Send(t, method, path, body)
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
	return scimtest.Decode[core.User](t, res)
}

func (c scimClient) group(t *testing.T, id string) core.Group {
	res := c.get(t, scimGroupsPath+"/"+id)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimtest.Decode[core.Group](t, res)
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
	return scimtest.Decode[T](t, res)
}

func scimList[T any](t *testing.T, c scimClient, path string, query url.Values) protocol.ListResponse[T] {
	res := c.get(t, path+"?"+query.Encode())
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimtest.Decode[protocol.ListResponse[T]](t, res)
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
	return scimtest.Decode[protocol.ListResponse[map[string]any]](t, res)
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
	return core.Member{Value: user.ID, Type: "User"}
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
