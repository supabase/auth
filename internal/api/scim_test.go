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

func TestSCIM(t *testing.T) {
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
}

func TestSCIMAuthentication(t *testing.T) {
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

		for _, base := range []string{scimUsersPath, scimGroupsPath} {
			id := base + "/" + scimMissingID
			for _, route := range [][2]string{{http.MethodGet, base}, {http.MethodPost, base}, {http.MethodPost, base + "/.search"}, {http.MethodGet, id}, {http.MethodPut, id}, {http.MethodPatch, id}, {http.MethodDelete, id}} {
				require.Equal(t, http.StatusUnauthorized, c.as(raw).do(t, route[0], route[1], map[string]any{}).StatusCode, route)
			}
		}
	})

	t.Run("rejects a token after SCIM is disabled for the provider", func(t *testing.T) {
		other := newSCIMClient(t, nil)
		require.Equal(t, http.StatusOK, other.get(t, scimUsersPath).StatusCode)

		res := other.admin(t, http.MethodDelete, "/admin/sso/providers/"+other.provider.ID.String()+"/scim", nil)
		require.Equal(t, http.StatusOK, res.StatusCode)

		require.Equal(t, http.StatusUnauthorized, other.get(t, scimUsersPath).StatusCode)
	})
}

func TestSCIMAdmin(t *testing.T) {
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

		for _, id := range []string{uuid.NewV4().String(), "not-a-uuid", foreign.ID.String()} {
			require.Equal(t, http.StatusNotFound, revoke(t, id).StatusCode, id)
		}
	})
}

func TestSCIMUsers(t *testing.T) {
	c := newSCIMClient(t, nil)

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

	t.Run("GET returns a user", func(t *testing.T) {
		user := c.createUser(t, scimUserName("bjensen"))

		res := c.get(t, scimUsersPath+"/"+user.ID)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Empty(t, res.Header.Get("ETag"))
		require.Equal(t, user, scimDecode[core.User](t, res))
	})

	t.Run("GET filters by userName", func(t *testing.T) {
		user := c.createUser(t, scimUserName("bjensen"))
		c.createUser(t, scimUserName("jsmith"))

		list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}})
		require.Equal(t, 1, list.TotalResults)
		require.Len(t, list.Resources, 1)
		require.Equal(t, user.ID, list.Resources[0].ID)
	})

	t.Run("GET sorts and paginates", func(t *testing.T) {
		tag := uuid.NewV4().String()
		second := c.createUser(t, "b+"+tag+"@example.com")
		first := c.createUser(t, "a+"+tag+"@example.com")

		list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}, "sortBy": {"userName"}, "sortOrder": {"descending"}, "startIndex": {"2"}, "count": {"1"}})
		require.Equal(t, 2, list.TotalResults)
		require.Len(t, list.Resources, 1)
		require.Equal(t, first.ID, list.Resources[0].ID)

		created := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}})
		require.Equal(t, []string{second.ID, first.ID}, []string{created.Resources[0].ID, created.Resources[1].ID})

		for startIndex, want := range map[string]int{"1": 2, "2": 1, "5": 0} {
			list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}, "startIndex": {startIndex}, "count": {"5"}})
			require.Equal(t, 2, list.TotalResults, startIndex)
			require.Len(t, list.Resources, want, startIndex)
		}
	})

	t.Run("POST ignores read-only groups", func(t *testing.T) {
		group := c.createGroup(t, "readonly-"+uuid.NewV4().String())
		body := newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen")
		body["groups"] = []map[string]any{{"value": group.ID}}
		res := c.do(t, http.MethodPost, scimUsersPath, body)
		require.Equal(t, http.StatusCreated, res.StatusCode)
		user := scimDecode[core.User](t, res)
		require.Empty(t, user.Groups)
		require.Empty(t, c.user(t, user.ID).Groups)
	})

	t.Run("GET sorts by nested and multi-valued attributes", func(t *testing.T) {
		tag := uuid.NewV4().String()
		create := func(userName, familyName string) string {
			res := c.do(t, http.MethodPost, scimUsersPath, newSCIMUser(userName+"+"+tag+"@example.com", "Barbara", familyName))
			require.Equal(t, http.StatusCreated, res.StatusCode)
			return scimDecode[core.User](t, res).ID
		}
		a, b := create("a", "Zulu"), create("b", "Alpha")

		for sortBy, want := range map[string][]string{"userName": {a, b}, "emails.value": {a, b}, "name.familyName": {b, a}} {
			list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {`userName co "` + tag + `"`}, "sortBy": {sortBy}})
			got := []string{}
			for _, user := range list.Resources {
				got = append(got, user.ID)
			}
			require.Equal(t, want, got, sortBy)
		}
	})

	t.Run("GET returns only the requested attributes", func(t *testing.T) {
		user := c.createUser(t, scimUserName("bjensen"))

		for _, query := range []url.Values{{"attributes": {"userName"}}, {"excludedAttributes": {"name"}}} {
			res := c.get(t, scimUsersPath+"/"+user.ID+"?"+query.Encode())
			require.Equal(t, http.StatusOK, res.StatusCode)
			got := scimDecode[core.User](t, res)
			require.Equal(t, user.UserName, got.UserName)
			require.Zero(t, got.Name)
		}
	})

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

	t.Run("DELETE removes a user", func(t *testing.T) {
		user := c.createUser(t, scimUserName("bjensen"))

		require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+user.ID).StatusCode)
		require.Equal(t, http.StatusNotFound, c.get(t, scimUsersPath+"/"+user.ID).StatusCode)
		filter := `userName eq "` + user.UserName + `"`
		require.Zero(t, scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}}).TotalResults)
		require.Zero(t, scimSearch(t, c, scimUsersPath, map[string]any{"filter": filter}).TotalResults)
	})
}

func TestSCIMGroups(t *testing.T) {
	c := newSCIMClient(t, nil)

	createUser := func(t *testing.T) core.User {
		return c.createUser(t, scimUserName("member"))
	}
	create := func(t *testing.T, members ...core.User) core.Group {
		return c.createGroup(t, "Tour Guides "+uuid.NewV4().String(), members...)
	}
	patch := func(t *testing.T, id string, operation map[string]any) *http.Response {
		return c.do(t, http.MethodPatch, scimGroupsPath+"/"+id, newSCIMPatch(operation))
	}

	t.Run("POST creates a group with members", func(t *testing.T) {
		user := createUser(t)
		displayName := "Tour Guides " + uuid.NewV4().String()

		res := c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(displayName, user))
		require.Equal(t, http.StatusCreated, res.StatusCode)
		require.Equal(t, protocol.MediaType, res.Header.Get("Content-Type"))
		group := scimDecode[core.Group](t, res)
		require.NotEmpty(t, group.ID)
		require.Equal(t, displayName, group.DisplayName)
		require.Equal(t, []core.Member{scimMember(user)}, group.Members)
	})

	t.Run("GET returns a group", func(t *testing.T) {
		group := create(t, createUser(t))

		require.Equal(t, group, c.group(t, group.ID))
	})

	t.Run("GET filters by displayName", func(t *testing.T) {
		group := create(t)
		create(t)

		list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`displayName eq "` + group.DisplayName + `"`}})
		require.Equal(t, 1, list.TotalResults)
		require.Len(t, list.Resources, 1)
		require.Equal(t, group.ID, list.Resources[0].ID)
	})

	t.Run("GET sorts and paginates", func(t *testing.T) {
		tag := uuid.NewV4().String()
		first := c.createGroup(t, "a "+tag)
		c.createGroup(t, "b "+tag)

		list := scimList[core.Group](t, c, scimGroupsPath, url.Values{"filter": {`displayName co "` + tag + `"`}, "sortBy": {"displayName"}, "sortOrder": {"descending"}, "startIndex": {"2"}, "count": {"1"}})
		require.Equal(t, 2, list.TotalResults)
		require.Len(t, list.Resources, 1)
		require.Equal(t, first.ID, list.Resources[0].ID)
	})

	t.Run("PATCH adds members", func(t *testing.T) {
		user, other := createUser(t), createUser(t)
		group := create(t, user)

		require.Equal(t, http.StatusNoContent, c.addMembers(t, group.ID, other.ID).StatusCode)
		require.ElementsMatch(t, []core.Member{scimMember(user), scimMember(other)}, c.group(t, group.ID).Members)
	})

	t.Run("POST stores a repeated member once", func(t *testing.T) {
		user := createUser(t)

		res := c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup("Tour Guides "+uuid.NewV4().String(), user, user))
		require.Equal(t, http.StatusCreated, res.StatusCode)
		require.Equal(t, []core.Member{scimMember(user)}, scimDecode[core.Group](t, res).Members)
	})

	t.Run("PUT keeps a repeated existing member once", func(t *testing.T) {
		user := createUser(t)
		group := create(t, user)

		res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, user, user))
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, []core.Member{scimMember(user)}, c.group(t, group.ID).Members)
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

	t.Run("PUT replaces a group", func(t *testing.T) {
		group := create(t, createUser(t))
		other := createUser(t)

		res := c.do(t, http.MethodPut, scimGroupsPath+"/"+group.ID, newSCIMGroup(group.DisplayName, other))
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, []core.Member{scimMember(other)}, scimDecode[core.Group](t, res).Members)
	})

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

	t.Run("rejects members that are not live resources of the provider", func(t *testing.T) {
		deleted := createUser(t)
		require.Equal(t, http.StatusNoContent, c.delete(t, scimUsersPath+"/"+deleted.ID).StatusCode)
		foreign := newSCIMClient(t, nil).createUser(t, scimUserName("foreign"))
		group := create(t)

		for name, value := range map[string]string{"unknown": scimMissingID, "foreign": foreign.ID, "deleted": deleted.ID, "malformed": "bjensen"} {
			members := []core.Member{{Value: value}}
			t.Run("POST "+name, func(t *testing.T) {
				body := newSCIMGroup("Tour Guides " + uuid.NewV4().String())
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

	t.Run("nests a group in a group", func(t *testing.T) {
		child := create(t)
		parent := create(t)

		require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)
		require.Equal(t, []core.Member{{Value: child.ID, Ref: child.Meta.Location, Type: "Group"}}, c.group(t, parent.ID).Members)
	})

	t.Run("derives direct and indirect user groups", func(t *testing.T) {
		user := createUser(t)
		child := create(t, user)
		parent := create(t)
		require.Equal(t, http.StatusNoContent, c.addMembers(t, parent.ID, child.ID).StatusCode)
		groups := []core.GroupMembership{
			{Value: child.ID, Ref: child.Meta.Location, Display: child.DisplayName, Type: "direct"},
			{Value: parent.ID, Ref: parent.Meta.Location, Display: parent.DisplayName, Type: "indirect"},
		}

		require.Equal(t, groups, c.user(t, user.ID).Groups)
		for _, filter := range []string{
			`groups.value eq "` + parent.ID + `"`,
			`groups[value eq "` + child.ID + `"]`,
		} {
			list := scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}})
			require.Len(t, list.Resources, 1, filter)
			require.Equal(t, user.ID, list.Resources[0].ID)
			require.Equal(t, groups, list.Resources[0].Groups)
		}
		for group, want := range map[string]int{parent.ID: 0, uuid.NewV4().String(): 1} {
			filter := `userName eq "` + user.UserName + `" and not (groups.value eq "` + group + `")`
			require.Len(t, scimList[core.User](t, c, scimUsersPath, url.Values{"filter": {filter}}).Resources, want, filter)
		}

		require.Equal(t, http.StatusNoContent, c.delete(t, scimGroupsPath+"/"+child.ID).StatusCode)
		require.Empty(t, c.user(t, user.ID).Groups)
	})

	t.Run("rejects cyclic members", func(t *testing.T) {
		bottom := create(t)
		middle := create(t)
		top := create(t)
		add := func(group, member core.Group) *http.Response {
			return c.addMembers(t, group.ID, member.ID)
		}
		require.Equal(t, http.StatusNoContent, add(top, middle).StatusCode)
		require.Equal(t, http.StatusNoContent, add(middle, bottom).StatusCode)

		for name, tc := range map[string]struct{ group, member core.Group }{
			"self":     {bottom, bottom},
			"parent":   {middle, top},
			"ancestor": {bottom, top},
		} {
			t.Run(name, func(t *testing.T) {
				res := add(tc.group, tc.member)
				requireSCIMError(t, res, http.StatusBadRequest, scimerrors.InvalidValue)
			})
		}
	})

	t.Run("rejects nesting deeper than the limit", func(t *testing.T) {
		chain := []core.Group{create(t)}
		for len(chain) < models.SCIMMaxDepth {
			chain = append(chain, create(t))
			require.Equal(t, http.StatusNoContent, c.addMembers(t, chain[len(chain)-2].ID, chain[len(chain)-1].ID).StatusCode)
		}
		bottom := chain[len(chain)-1]
		require.Equal(t, http.StatusNoContent, c.addMembers(t, bottom.ID, createUser(t).ID).StatusCode)
		requireSCIMError(t, c.addMembers(t, bottom.ID, create(t).ID), http.StatusBadRequest, scimerrors.InvalidValue)
		requireSCIMError(t, c.addMembers(t, create(t).ID, chain[0].ID), http.StatusBadRequest, scimerrors.InvalidValue)

		shortcut := create(t)
		require.Equal(t, http.StatusNoContent, c.addMembers(t, shortcut.ID, chain[len(chain)-2].ID).StatusCode)
		require.Equal(t, http.StatusNoContent, c.addMembers(t, chain[len(chain)-2].ID, create(t).ID).StatusCode)
		pair := create(t)
		require.Equal(t, http.StatusNoContent, c.addMembers(t, pair.ID, create(t).ID).StatusCode)
		requireSCIMError(t, c.addMembers(t, chain[len(chain)-2].ID, pair.ID), http.StatusBadRequest, scimerrors.InvalidValue)
	})

	t.Run("rejects a deep foreign group as invalid, not as too deep", func(t *testing.T) {
		other := newSCIMClient(t, nil)
		chain := []core.Group{other.createGroup(t, "Foreign "+uuid.NewV4().String())}
		for len(chain) < models.SCIMMaxDepth {
			chain = append(chain, other.createGroup(t, "Foreign "+uuid.NewV4().String()))
			require.Equal(t, http.StatusNoContent, other.addMembers(t, chain[len(chain)-2].ID, chain[len(chain)-1].ID).StatusCode)
		}
		body := requireSCIMError(t, c.addMembers(t, create(t).ID, create(t).ID, chain[0].ID), http.StatusBadRequest, scimerrors.InvalidValue)
		require.Contains(t, body.Detail, "is not a valid members value")
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
}

func TestSCIMIsolation(t *testing.T) {
	c, other := newSCIMClient(t, nil), newSCIMClient(t, nil)
	user := c.createUser(t, scimUserName("bjensen"))
	group := c.createGroup(t, "Tour Guides "+uuid.NewV4().String(), user)

	userPath, groupPath := scimUsersPath+"/"+user.ID, scimGroupsPath+"/"+group.ID
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, userPath, nil},
		{http.MethodPut, userPath, newSCIMUser(scimUserName("jsmith"), "John", "Smith")},
		{http.MethodPatch, userPath, newSCIMPatch(map[string]any{"op": "replace", "path": "active", "value": false})},
		{http.MethodDelete, userPath, nil},
		{http.MethodGet, groupPath, nil},
		{http.MethodPut, groupPath, newSCIMGroup("Group B")},
		{http.MethodPatch, groupPath, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Group B"})},
		{http.MethodDelete, groupPath, nil},
	} {
		requireSCIMError(t, other.do(t, tc.method, tc.path, tc.body), http.StatusNotFound, "")
	}
	require.Zero(t, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).TotalResults)
	require.Zero(t, scimList[core.Group](t, other, scimGroupsPath, url.Values{"filter": {`displayName eq "` + group.DisplayName + `"`}}).TotalResults)
	require.Zero(t, scimSearch(t, other, scimUsersPath, map[string]any{"filter": `userName eq "` + user.UserName + `"`}).TotalResults)
	require.Zero(t, scimSearch(t, other, scimGroupsPath, map[string]any{"filter": `displayName eq "` + group.DisplayName + `"`}).TotalResults)
	twin := other.createUser(t, user.UserName)
	require.Equal(t, []core.User{twin}, scimList[core.User](t, other, scimUsersPath, url.Values{"filter": {`userName eq "` + user.UserName + `"`}}).Resources)
	user.Groups = []core.GroupMembership{{Value: group.ID, Ref: group.Meta.Location, Display: group.DisplayName, Type: "direct"}}
	require.Equal(t, user, c.user(t, user.ID))
	require.Equal(t, group, c.group(t, group.ID))
}

func TestSCIMSearch(t *testing.T) {
	c := newSCIMClient(t, nil)
	user := c.createUser(t, scimUserName("bjensen"))
	c.createUser(t, scimUserName("jsmith"))
	group := c.createGroup(t, "Tour Guides", user)

	t.Run("filters Users", func(t *testing.T) {
		list := scimSearch(t, c, scimUsersPath, map[string]any{"filter": `userName eq "` + user.UserName + `"`, "attributes": []string{"userName"}})
		require.Equal(t, 1, list.TotalResults)
		require.Equal(t, []map[string]any{{"id": user.ID, "userName": user.UserName, "schemas": []any{string(core.SchemaUser)}}}, list.Resources)
	})

	t.Run("filters Groups", func(t *testing.T) {
		list := scimSearch(t, c, scimGroupsPath, map[string]any{"filter": `displayName eq "Tour Guides"`, "excludedAttributes": []string{"members"}})
		require.Equal(t, 1, list.TotalResults)
		require.Equal(t, group.ID, list.Resources[0]["id"])
		require.NotContains(t, list.Resources[0], "members")
	})
}

func TestSCIMErrors(t *testing.T) {
	c := newSCIMClient(t, nil)
	user := c.createUser(t, scimUserName("bjensen"))
	missingUser, missingGroup := scimUsersPath+"/"+scimMissingID, scimGroupsPath+"/"+scimMissingID
	deactivate := newSCIMPatch(map[string]any{"op": "replace", "path": "active", "value": false})

	for _, tc := range []struct {
		name, method, path string
		body               any
		status             int
	}{
		{"GET unknown user", http.MethodGet, missingUser, nil, http.StatusNotFound},
		{"PUT unknown user", http.MethodPut, missingUser, newSCIMUser(scimUserName("bjensen"), "Barbara", "Jensen"), http.StatusNotFound},
		{"PATCH unknown user", http.MethodPatch, missingUser, deactivate, http.StatusNotFound},
		{"DELETE unknown user", http.MethodDelete, missingUser, nil, http.StatusNotFound},
		{"GET unknown group", http.MethodGet, missingGroup, nil, http.StatusNotFound},
		{"PUT unknown group", http.MethodPut, missingGroup, newSCIMGroup("Tour Guides"), http.StatusNotFound},
		{"PATCH unknown group", http.MethodPatch, missingGroup, newSCIMPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Group B"}), http.StatusNotFound},
		{"DELETE unknown group", http.MethodDelete, missingGroup, nil, http.StatusNotFound},
		{"POST user without userName", http.MethodPost, scimUsersPath, map[string]any{"schemas": []core.SchemaURI{core.SchemaUser}}, http.StatusBadRequest},
		{"POST group without displayName", http.MethodPost, scimGroupsPath, map[string]any{"schemas": []core.SchemaURI{core.SchemaGroup}}, http.StatusBadRequest},
		{"PATCH unknown op", http.MethodPatch, scimUsersPath + "/" + user.ID, newSCIMPatch(map[string]any{"op": "bogus", "path": "active", "value": false}), http.StatusBadRequest},
		{"PATCH unknown path", http.MethodPatch, scimUsersPath + "/" + user.ID, newSCIMPatch(map[string]any{"op": "replace", "path": "nope", "value": "x"}), http.StatusBadRequest},
		{"GET users with an invalid filter", http.MethodGet, scimUsersPath + "?" + url.Values{"filter": {"userName eq"}}.Encode(), nil, http.StatusBadRequest},
		{"GET groups with an invalid filter", http.MethodGet, scimGroupsPath + "?" + url.Values{"filter": {"displayName eq"}}.Encode(), nil, http.StatusBadRequest},
		{"GET groups with an unsupported members filter", http.MethodGet, scimGroupsPath + "?" + url.Values{"filter": {`members.value co "x"`}}.Encode(), nil, http.StatusBadRequest},
		{"GET users with an id sw filter", http.MethodGet, scimUsersPath + "?" + url.Values{"filter": {`id sw "x"`}}.Encode(), nil, http.StatusBadRequest},
		{"GET users with a groups type filter", http.MethodGet, scimUsersPath + "?" + url.Values{"filter": {`groups[type eq "direct"]`}}.Encode(), nil, http.StatusBadRequest},
		{"GET users with an unknown sortBy", http.MethodGet, scimUsersPath + "?sortBy=nope", nil, http.StatusBadRequest},
		{"POST /.search", http.MethodPost, "/scim/v2/.search", map[string]any{}, http.StatusNotImplemented},
		{"POST /Users/.search without the SearchRequest schema", http.MethodPost, scimUsersPath + "/.search", map[string]any{}, http.StatusBadRequest},
		{"POST /Groups/.search without the SearchRequest schema", http.MethodPost, scimGroupsPath + "/.search", map[string]any{}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := c.do(t, tc.method, tc.path, tc.body)
			requireSCIMError(t, res, tc.status, "")
		})
	}
}

func TestSCIMUniqueness(t *testing.T) {
	c := newSCIMClient(t, nil)
	externalID := uuid.NewV4().String()
	withExternalID := func(userName string) map[string]any {
		user := newSCIMUser(userName, "Barbara", "Jensen")
		user["externalId"] = externalID
		return user
	}
	res := c.do(t, http.MethodPost, scimUsersPath, withExternalID(scimUserName("bjensen")))
	require.Equal(t, http.StatusCreated, res.StatusCode)
	user := scimDecode[core.User](t, res)
	other := c.createUser(t, scimUserName("jsmith"))

	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"POST duplicate userName", http.MethodPost, scimUsersPath, newSCIMUser(user.UserName, "Barbara", "Jensen")},
		{"POST duplicate externalId", http.MethodPost, scimUsersPath, withExternalID(scimUserName("bjensen"))},
		{"PUT duplicate userName", http.MethodPut, scimUsersPath + "/" + other.ID, newSCIMUser(user.UserName, "John", "Smith")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := c.do(t, tc.method, tc.path, tc.body)
			body := requireSCIMError(t, res, http.StatusConflict, scimerrors.Uniqueness)
			require.Equal(t, "resource must be unique", body.Detail)
		})
	}
}

func TestSCIMFilters(t *testing.T) {
	c := newSCIMClient(t, nil)
	enterprise := string(core.SchemaEnterpriseUser)
	res := c.do(t, http.MethodPost, scimUsersPath, map[string]any{"schemas": []string{string(core.SchemaUser)}, "userName": "decoy@example.com"})
	require.Equal(t, http.StatusCreated, res.StatusCode)
	decoy := scimDecode[core.User](t, res)
	res = c.do(t, http.MethodPost, scimUsersPath, map[string]any{
		"schemas":           []string{string(core.SchemaUser), enterprise},
		"externalId":        "701984",
		"userName":          "bjensen@example.com",
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
		"phoneNumbers":      []map[string]any{{"value": "555-555-8377", "type": "mobile"}},
		"ims":               []map[string]any{{"value": "babsj", "type": "xmpp"}},
		"photos":            []map[string]any{{"value": "https://photos.example.com/bjensen.jpg", "type": "photo"}},
		"addresses":         []map[string]any{{"formatted": "100 Universal City Plaza", "streetAddress": "100 Universal City Plaza", "locality": "Hollywood", "region": "CA", "postalCode": "91608", "country": "US", "type": "home", "primary": true}},
		"entitlements":      []map[string]any{{"value": "tour-guide-badge"}},
		"roles":             []map[string]any{{"value": "guide"}},
		"x509Certificates":  []map[string]any{{"value": "dGVzdA=="}},
		enterprise:          map[string]any{"employeeNumber": "701984", "costCenter": "4130", "organization": "Universal Studios", "division": "Theme Park", "department": "Tour Operations", "manager": map[string]any{"value": decoy.ID}},
	})
	require.Equal(t, http.StatusCreated, res.StatusCode)
	user := scimDecode[core.User](t, res)

	body := newSCIMGroup("Decoys", decoy)
	body["externalId"] = "Tour-Guides"
	res = c.do(t, http.MethodPost, scimGroupsPath, body)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	decoys := scimDecode[core.Group](t, res)
	body = newSCIMGroup("Tour Guides", user)
	body["externalId"] = "tour-guides"
	res = c.do(t, http.MethodPost, scimGroupsPath, body)
	require.Equal(t, http.StatusCreated, res.StatusCode)
	group := scimDecode[core.Group](t, res)

	for _, tc := range []struct{ path, filter, id string }{
		{scimUsersPath, `id eq "` + user.ID + `"`, user.ID},
		{scimUsersPath, `externalId eq "701984"`, user.ID},
		{scimUsersPath, `meta.created gt "` + decoy.Meta.Created.Format(time.RFC3339Nano) + `"`, user.ID},
		{scimUsersPath, `meta.lastModified gt "` + decoy.Meta.LastModified.Format(time.RFC3339Nano) + `"`, user.ID},
		{scimUsersPath, `meta.created ge "` + user.Meta.Created.Format(time.RFC3339Nano) + `"`, user.ID},
		{scimUsersPath, `meta.created le "` + decoy.Meta.Created.Format(time.RFC3339Nano) + `"`, decoy.ID},
		{scimUsersPath, `userName eq "bjensen@example.com"`, user.ID},
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
		{scimUsersPath, `phoneNumbers.value eq "555-555-8377"`, user.ID},
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
		{scimGroupsPath, `members.value eq "` + user.ID + `"`, group.ID},
		{scimGroupsPath, `members[value eq "` + user.ID + `"]`, group.ID},
		{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members.value eq "` + user.ID + `"`, group.ID},
		{scimGroupsPath, strings.ToLower(string(core.SchemaGroup)) + `:members[value eq "` + user.ID + `"]`, group.ID},
		{scimGroupsPath, `members[type eq "user" and value eq "` + user.ID + `"]`, group.ID},
		{scimGroupsPath, `displayName eq "Tour Guides" and members[value eq "` + user.ID + `"]`, group.ID},
		{scimGroupsPath, `externalId eq "tour-guides" and members pr`, group.ID},
		{scimGroupsPath, `not (members[value eq "` + decoy.ID + `"])`, group.ID},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			list := scimList[core.Base](t, c, tc.path, url.Values{"filter": {tc.filter}})
			ids := []string{}
			for _, resource := range list.Resources {
				ids = append(ids, resource.ID)
			}
			require.Equal(t, []string{tc.id}, ids)
		})
	}

	t.Run("refuses a password filter in the URL as sensitive", func(t *testing.T) {
		res := c.get(t, scimUsersPath+"?"+url.Values{"filter": {`password eq "t1meMa$heen"`}}.Encode())
		requireSCIMError(t, res, http.StatusForbidden, scimerrors.Sensitive)
	})
}

func TestSCIMOktaReplay(t *testing.T) {
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
	res := c.do(t, http.MethodPost, scimUsersPath, newSCIMUser(userName, "Barbara", "Jensen"))
	require.Equal(t, http.StatusCreated, res.StatusCode)
	return scimDecode[core.User](t, res)
}

func (c scimClient) createGroup(t *testing.T, displayName string, members ...core.User) core.Group {
	res := c.do(t, http.MethodPost, scimGroupsPath, newSCIMGroup(displayName, members...))
	require.Equal(t, http.StatusCreated, res.StatusCode)
	return scimDecode[core.Group](t, res)
}

func (c scimClient) addMembers(t *testing.T, id string, values ...string) *http.Response {
	members := make([]core.Member, len(values))
	for i, value := range values {
		members[i] = core.Member{Value: value}
	}
	return c.do(t, http.MethodPatch, scimGroupsPath+"/"+id, newSCIMPatch(map[string]any{"op": "add", "path": "members", "value": members}))
}

func (c scimClient) requireGroup(t *testing.T, id, displayName string, members ...string) {
	group := c.group(t, id)
	require.Equal(t, displayName, group.DisplayName)
	values := []string{}
	for _, member := range group.Members {
		values = append(values, member.Value)
	}
	require.ElementsMatch(t, members, values)
}

func scimFixture(t *testing.T, name string) []byte {
	root, err := os.OpenRoot("testdata/scim")
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	raw, err := root.ReadFile(name)
	require.NoError(t, err)
	return raw
}

func scimList[T any](t *testing.T, c scimClient, path string, query url.Values) protocol.ListResponse[T] {
	res := c.get(t, path+"?"+query.Encode())
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[protocol.ListResponse[T]](t, res)
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

func scimSearch(t *testing.T, c scimClient, path string, body map[string]any) protocol.ListResponse[map[string]any] {
	body["schemas"] = []core.SchemaURI{protocol.SchemaSearchRequest}
	res := c.do(t, http.MethodPost, path+"/.search", body)
	require.Equal(t, http.StatusOK, res.StatusCode)
	return scimDecode[protocol.ListResponse[map[string]any]](t, res)
}

func scimUserName(prefix string) string {
	return prefix + "+" + uuid.NewV4().String() + "@example.com"
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
	return core.Member{Value: user.ID, Ref: user.Meta.Location, Type: "User"}
}

func newSCIMPatch(operations ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{string(protocol.SchemaPatchOp)},
		"Operations": operations,
	}
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
