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
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimtest"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/models"
)

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

func (c scimClient) adminPath() string {
	return "/admin/sso/providers/" + c.provider.ID.String() + "/scim"
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
	members := make([]core.Member, len(values))
	for i, value := range values {
		members[i] = core.Member{Value: value}
	}
	return c.api.Send(t, http.MethodPatch, scimGroupsPath+"/"+id, newSCIMPatch(map[string]any{"op": "add", "path": "members", "value": members}))
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

func scimCreate[T any](t *testing.T, c scimClient, path string, body any) T {
	res := c.api.Send(t, http.MethodPost, path, body)
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
	res := c.api.Send(t, http.MethodPost, path+"/.search", body)
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

func newSCIMBoss(displayName string) map[string]any {
	body := newSCIMUser(scimUserName("boss"), "Barbara", "Jensen")
	body["displayName"] = displayName
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
				res := c.api.Send(t, request.Method, path, body)
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
