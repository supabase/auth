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
			inst := newSCIMInstance(t, func(config *conf.GlobalConfiguration) {
				config.SSO.SCIM.Enabled = false
			})
			api := scimtest.NewClient(inst.APIServer.URL, scimtest.WithHTTPClient(inst.APIClient))

			for _, path := range append(scimPaths, "/scim/v2/Unknown") {
				res := api.Get(t, path)
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
				res := c.api.Get(t, tc.path)
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
				require.Contains(t, string(scimBody(t, res)), tc.schema)
			})
		}

		t.Run("ServiceProviderConfig matches the fixture", func(t *testing.T) {
			fixture := scimFixture(t, "service_provider_config.json")

			res := c.api.Get(t, scimServiceProviderConfigPath)
			require.JSONEq(t, string(fixture), string(scimBody(t, res)))
		})

		t.Run("Location trims a trailing slash from the external URL", func(t *testing.T) {
			c := newSCIMClient(t, func(config *conf.GlobalConfiguration) {
				config.API.ExternalURL = "https://auth.example.com/"
			})

			res := c.api.Get(t, scimServiceProviderConfigPath)
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
				res := c.api.With(scimtest.WithRequest(func(r *http.Request) {
					r.Header.Del("Authorization")
					if tc.authorization != "" {
						r.Header.Set("Authorization", tc.authorization)
					}
				})).Get(t, scimUsersPath)

				require.Equal(t, tc.status, res.StatusCode)
				require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
				require.Equal(t, tc.challenge, res.Header.Get("WWW-Authenticate"))
			})
		}

		t.Run("rejects a revoked token", func(t *testing.T) {
			token, raw, err := models.CreateSCIMToken(c.inst.Conn, uuid.UUID(c.provider.ID), nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, c.as(raw).api.Get(t, scimUsersPath).StatusCode)

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
			require.Equal(t, http.StatusOK, other.api.Get(t, scimUsersPath).StatusCode)

			res := other.admin(t, http.MethodDelete, "/admin/sso/providers/"+other.provider.ID.String()+"/scim", nil)
			require.Equal(t, http.StatusOK, res.StatusCode)

			require.Equal(t, http.StatusUnauthorized, other.api.Get(t, scimUsersPath).StatusCode)
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
			require.Equal(t, http.StatusOK, c.as(token.Token).api.Get(t, scimUsersPath).StatusCode)
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

			require.Equal(t, http.StatusUnauthorized, c.as(token.Token).api.Get(t, scimUsersPath).StatusCode)
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

	t.Run("Delete", func(t *testing.T) {
		t.Run("DELETE drops the manager and bumps linked versions", func(t *testing.T) {
			boss := scimCreate[core.User](t, c, scimUsersPath, newSCIMBoss("Leaving Boss"))
			report := scimCreate[core.User](t, c, scimUsersPath, newSCIMReport(boss.ID))
			group := c.createGroup(t, "Bosses "+uuid.NewV7().String(), boss)
			require.NotEqual(t, boss.Meta.Version, c.user(t, boss.ID).Meta.Version)

			require.Equal(t, http.StatusNoContent, c.api.Delete(t, scimUsersPath+"/"+boss.ID).StatusCode)
			after := c.user(t, report.ID)
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

			ids := scimIDs(t, c, scimUsersPath, url.Values{"filter": {string(core.SchemaEnterpriseUser) + `:manager.value eq "jane@example.com"`}})
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

	t.Run("Create", func(t *testing.T) {
		t.Run("POST stores a repeated member once", func(t *testing.T) {
			user := createUser(t)

			require.Equal(t, []core.Member{scimMember(user)}, scimCreate[core.Group](t, c, scimGroupsPath, newSCIMGroup("Tour Guides "+uuid.NewV7().String(), user, user)).Members)
		})

		t.Run("rejects members that are not live resources of the provider", func(t *testing.T) {
			deleted := createUser(t)
			require.Equal(t, http.StatusNoContent, c.api.Delete(t, scimUsersPath+"/"+deleted.ID).StatusCode)
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

	})

	t.Run("Read", func(t *testing.T) {
		t.Run("GET omits members when excluded", func(t *testing.T) {
			group := create(t, createUser(t))

			list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`id eq "` + group.ID + `"`}, "excludedAttributes": {"members"}})
			require.Len(t, list.Resources, 1)
			require.Empty(t, list.Resources[0].Members)

			res := c.api.Get(t, scimGroupsPath+"/"+group.ID+"?excludedAttributes=members")
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
	})

	t.Run("Patch", func(t *testing.T) {
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

			require.Equal(t, http.StatusNoContent, c.api.Delete(t, scimGroupsPath+"/"+child.ID).StatusCode)
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
			decoy := scimCreate[core.User](t, c, scimUsersPath, map[string]any{"schemas": []string{string(core.SchemaUser)}, "userName": "decoy@example.com"})
			user := scimCreate[core.User](t, c, scimUsersPath, newSCIMFullUser("bjensen@example.com", "701984", decoy.ID))

			for _, filter := range []string{
				`title co null or userName eq "decoy@example.com"`,
				`meta.location eq "https://example.org/` + user.ID + `" or userName eq "decoy@example.com"`,
				`meta.version ne "bad" and userName eq "decoy@example.com"`,
			} {
				t.Run(filter, func(t *testing.T) {
					require.Equal(t, []string{decoy.ID}, scimIDs(t, c, scimUsersPath, url.Values{"filter": {filter}}))
				})
			}
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
					res := c.api.Get(t, tc.path+"?"+url.Values{"filter": {tc.filter}}.Encode())
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

func (c scimClient) do(t *testing.T, method, path string, body any) *http.Response {
	return c.api.Send(t, method, path, body)
}

func (c scimClient) admin(t *testing.T, method, path string, body any) *http.Response {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, path, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.inst.DoAdmin(req)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, res.Body.Close()) })
	return res
}

func (c scimClient) user(t *testing.T, id string) core.User {
	res := c.api.Get(t, scimUsersPath+"/"+id)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimtest.Decode[core.User](t, res)
}

func (c scimClient) group(t *testing.T, id string) core.Group {
	res := c.api.Get(t, scimGroupsPath+"/"+id)
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
	res := c.api.Get(t, path+"?"+query.Encode())
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

func newSCIMFullUser(userName, externalID, managerID string) map[string]any {
	enterprise := string(core.SchemaEnterpriseUser)
	return map[string]any{
		"schemas":      []string{string(core.SchemaUser), enterprise},
		"externalId":   externalID,
		"userName":     userName,
		"name":         map[string]any{"familyName": "Jensen-Smith", "givenName": "Babs", "honorificPrefix": "Ms."},
		"displayName":  "Babs Jensen",
		"nickName":     "Babsy",
		"title":        "Tour Guide",
		"active":       false,
		"emails":       []map[string]any{{"value": "babs@jensen.org", "type": "home", "primary": true}},
		"phoneNumbers": []map[string]any{{"value": "555-555-8377", "type": "mobile", "primary": true}},
		"addresses":    []map[string]any{{"country": "US", "type": "home", "primary": true}},
		enterprise:     map[string]any{"employeeNumber": "701984", "department": "Tour Operations", "manager": map[string]any{"value": managerID}},
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
