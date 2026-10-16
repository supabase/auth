package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/scimtest"
	"github.com/supabase/auth/internal/conf"
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
					res := c.api.Send(t, tc.method, tc.path, nil)
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

			res := c.admin(t, http.MethodDelete, c.adminPath()+"/tokens/"+token.ID.String(), nil)
			require.Equal(t, http.StatusOK, res.StatusCode)

			routes := scimItemRoutes(scimMissingID, scimMissingID)
			for _, base := range []string{scimUsersPath, scimGroupsPath} {
				routes = append(routes, scimRoute{http.MethodGet, base, nil}, scimRoute{http.MethodPost, base, map[string]any{}}, scimRoute{http.MethodPost, base + "/.search", map[string]any{}})
			}
			for _, route := range routes {
				require.Equal(t, http.StatusUnauthorized, c.as(raw).api.Send(t, route.method, route.path, route.body).StatusCode, route)
			}
		})

		t.Run("rejects a token after SCIM is disabled for the provider", func(t *testing.T) {
			other := newSCIMClient(t, nil)
			require.Equal(t, http.StatusOK, other.api.Get(t, scimUsersPath).StatusCode)

			res := other.admin(t, http.MethodDelete, other.adminPath(), nil)
			require.Equal(t, http.StatusOK, res.StatusCode)

			require.Equal(t, http.StatusUnauthorized, other.api.Get(t, scimUsersPath).StatusCode)
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
		require.Equal(t, http.StatusOK, c.api.Send(t, http.MethodPut, scimUsersPath+"/"+user.ID, body).StatusCode)
		require.NotContains(t, stored(t), password)
		require.Equal(t, http.StatusOK, c.api.Send(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "password", "value": password})).StatusCode)
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
					res := c.api.Send(t, http.MethodPost, scimGroupsPath, body)
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
			res = c.api.Send(t, http.MethodPatch, scimGroupsPath+"/"+group.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "renamed " + group.ID}))
			require.Equal(t, http.StatusOK, res.StatusCode)
			c.requireGroup(t, group.ID, "renamed "+group.ID, group.Members[0].Value)
		})
	})

	t.Run("Replace", func(t *testing.T) {
		t.Run("PUT keeps a repeated existing member once", func(t *testing.T) {
			user := createUser(t)
			group := create(t, user)

			res := c.api.Send(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, user, user))
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, []core.Member{scimMember(user)}, c.group(t, group.ID).Members)
		})
	})

	t.Run("Patch", func(t *testing.T) {
		t.Run("PATCH adds and removes members in one request", func(t *testing.T) {
			kept, removed, added, absent := createUser(t), createUser(t), createUser(t), createUser(t)
			group := create(t, kept, removed)

			res := c.api.Send(t, http.MethodPatch, scimGroupsPath+"/"+group.ID, newSCIMPatch(
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
			res := c.api.Send(t, http.MethodPatch, scimUsersPath+"/"+user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Babs"}))
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
			decoy := c.createUser(t, "decoy@example.com")
			titled := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
			titled["title"] = "Tour Guide"
			user := scimCreate[core.User](t, c, scimUsersPath, titled)

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

		t.Run("Go and Postgres fold the same characters", func(t *testing.T) {
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

		for _, route := range scimItemRoutes(scimMissingID, scimMissingID) {
			t.Run(route.method+" "+route.path, func(t *testing.T) {
				scimtest.RequireError(t, c.api.Send(t, route.method, route.path, route.body), http.StatusNotFound, "")
			})
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
			scimtest.RequireError(t, other.api.Send(t, route.method, route.path, route.body), http.StatusNotFound, "")
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
}

func TestSCIMOkta(t *testing.T) {
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
}
