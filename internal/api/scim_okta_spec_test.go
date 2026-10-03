package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
)

func (ts *SCIMTestSuite) okta(method, path, body string, headers ...string) (int, map[string]any) {
	contentType := "application/scim+json; charset=utf-8"
	if method == http.MethodPost {
		contentType = "application/json"
	}
	headers = append([]string{"Accept", "application/scim+json", "Accept-Charset", "utf-8", "User-Agent", "OKTA SCIM Integration"}, headers...)
	w, got := ts.doAs(contentType, ts.TokenA, method, path, body, headers...)
	return w.Code, got
}

const (
	rfcBjensen = "2819c223-7f76-453a-919d-413861904646"
	rfcJsmith  = "c75ad752-64ae-4823-840d-ffa80929976c"
	rfcBabs    = "6c5bb468-14b2-4183-baf2-06d523e03bd3"
	rfcGroup   = "e9e30dba-f08f-4109-8486-d5c6a331660a"
)

type replayRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

func (ts *SCIMTestSuite) replay(file, created string, ids []string, onRequest func(step string, request replayRequest, got map[string]any, id string), afterStep func(step, id string)) int {
	raw, err := fs.ReadFile(os.DirFS("testdata/scim"), file)
	require.NoError(ts.T(), err)
	var steps []struct {
		Step     string          `json:"step"`
		Requests []replayRequest `json:"requests"`
	}
	require.NoError(ts.T(), json.Unmarshal([]byte(strings.NewReplacer(ids...).Replace(string(raw))), &steps))

	id := created
	for _, step := range steps {
		for _, request := range step.Requests {
			request.Path = strings.ReplaceAll(strings.TrimPrefix(request.Path, "/scim/v2"), created, id)
			request.Body = json.RawMessage(strings.ReplaceAll(string(request.Body), created, id))
			status, got := ts.okta(request.Method, request.Path, string(request.Body))
			require.Less(ts.T(), status, 300, "%s: %s %s: %v", step.Step, request.Method, request.Path, got)
			if request.Method == http.MethodPost {
				id = got["id"].(string)
			}
			if onRequest != nil {
				onRequest(step.Step, request, got, id)
			}
		}
		afterStep(step.Step, id)
	}
	return len(steps)
}

func oktaFilter(userName string) string {
	return "/Users?" + url.Values{"filter": {`userName eq "` + userName + `"`}}.Encode()
}

func (ts *SCIMTestSuite) TestOktaSpec() {
	const (
		userName   = "okta.spec.user@example.com"
		givenName  = "Okta"
		familyName = "Spec"
	)
	const body = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","name":{"givenName":"` + givenName + `","familyName":"` + familyName + `"},"emails":[{"primary":true,"value":"` + userName + `","type":"work"}],"displayName":"` + givenName + " " + familyName + `","active":true}`
	requireError := func(got map[string]any, status string) {
		require.NotEmpty(ts.T(), got["detail"])
		require.Equal(ts.T(), status, got["status"])
		require.Contains(ts.T(), got["schemas"], string(protocol.SchemaError))
	}
	ts.create(ts.TokenA, oktaUser)

	status, got := ts.okta(http.MethodGet, "/Users?count=1&startIndex=1", "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Contains(ts.T(), got["schemas"], string(protocol.SchemaListResponse))
	require.IsType(ts.T(), float64(0), got["itemsPerPage"])
	require.IsType(ts.T(), float64(0), got["startIndex"])
	require.IsType(ts.T(), float64(0), got["totalResults"])
	require.NotEmpty(ts.T(), got["Resources"])
	first := got["Resources"].([]any)[0].(map[string]any)
	require.NotEmpty(ts.T(), first["id"])
	id := first["id"].(string)

	status, got = ts.okta(http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Equal(ts.T(), id, got["id"])
	for _, user := range []map[string]any{first, got} {
		require.NotEmpty(ts.T(), user["name"].(map[string]any)["familyName"])
		require.NotEmpty(ts.T(), user["name"].(map[string]any)["givenName"])
		require.NotEmpty(ts.T(), user["userName"])
		require.NotNil(ts.T(), user["active"])
		require.NotEmpty(ts.T(), user["emails"].([]any)[0].(map[string]any)["value"])
	}

	for _, missing := range []string{"invalid.user@example.com", userName} {
		status, got = ts.okta(http.MethodGet, oktaFilter(missing), "")
		require.Equal(ts.T(), http.StatusOK, status, missing)
		require.Contains(ts.T(), got["schemas"], string(protocol.SchemaListResponse), missing)
		require.EqualValues(ts.T(), 0, got["totalResults"], missing)
	}

	status, got = ts.okta(http.MethodGet, "/Users/010101", "")
	require.Equal(ts.T(), http.StatusNotFound, status)
	requireError(got, "404")

	status, got = ts.okta(http.MethodPost, "/Users", body)
	require.Equal(ts.T(), http.StatusCreated, status)
	require.Equal(ts.T(), true, got["active"])
	require.NotEmpty(ts.T(), got["id"])
	require.Equal(ts.T(), familyName, got["name"].(map[string]any)["familyName"])
	require.Equal(ts.T(), givenName, got["name"].(map[string]any)["givenName"])
	require.Contains(ts.T(), got["schemas"], string(core.SchemaUser))
	require.Equal(ts.T(), userName, got["userName"])
	created := got["id"].(string)

	status, got = ts.okta(http.MethodGet, "/Users/"+created, "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.Equal(ts.T(), userName, got["userName"])
	require.Equal(ts.T(), familyName, got["name"].(map[string]any)["familyName"])
	require.Equal(ts.T(), givenName, got["name"].(map[string]any)["givenName"])

	status, _ = ts.okta(http.MethodPost, "/Users", body)
	require.Equal(ts.T(), http.StatusConflict, status)

	status, got = ts.okta(http.MethodGet, oktaFilter(strings.ToUpper(userName)), "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.EqualValues(ts.T(), 1, got["totalResults"])
	require.Equal(ts.T(), created, got["Resources"].([]any)[0].(map[string]any)["id"])

	status, got = ts.okta(http.MethodGet, "/Groups", "")
	require.Equal(ts.T(), http.StatusOK, status)
	require.EqualValues(ts.T(), 0, got["totalResults"])

	status, got = ts.okta(http.MethodGet, oktaFilter(strings.ToUpper(userName)), "", "Authorization", "non-token")
	require.Equal(ts.T(), http.StatusUnauthorized, status)
	requireError(got, "401")

	status, got = ts.okta(http.MethodGet, "/Users/00919288221112222", "")
	require.Equal(ts.T(), http.StatusNotFound, status)
	requireError(got, "404")
}

func (ts *SCIMTestSuite) TestOktaUserLifecycleReplay() {
	const password = "okta-generated-password"

	type state struct {
		familyName string
		active     bool
		found      int
	}
	expected := map[string]state{
		"assign new user":           {"Smith", true, 0},
		"edit last name":            {"Jensen", true, -1},
		"unassign":                  {"Jensen", false, -1},
		"reassign (PUT sent twice)": {"Jensen", true, 1},
	}

	id, version := "", ""
	entries := ts.auditDuring(func() {
		played := ts.replay("okta_user_lifecycle.json", rfcBjensen, nil, func(step string, request replayRequest, got map[string]any, created string) {
			if strings.Contains(request.Path, "filter=") {
				want := expected[step]
				require.EqualValues(ts.T(), want.found, got["totalResults"], step)
				if want.found > 0 {
					require.Equal(ts.T(), created, got["Resources"].([]any)[0].(map[string]any)["id"], step)
				}
			}
			if request.Method == http.MethodPost {
				require.Contains(ts.T(), string(request.Body), password)
				require.NotContains(ts.T(), got, "password")
			}
		}, func(step, created string) {
			want, ok := expected[step]
			require.True(ts.T(), ok, step)
			id = created
			status, got := ts.okta(http.MethodGet, "/Users/"+id, "")
			require.Equal(ts.T(), http.StatusOK, status, step)
			require.Equal(ts.T(), want.familyName, got["name"].(map[string]any)["familyName"], step)
			require.Equal(ts.T(), want.active, got["active"], step)
			current := got["meta"].(map[string]any)["version"].(string)
			require.NotEqual(ts.T(), version, current, step)
			version = current

			require.Equal(ts.T(), 1, ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID), step)
		})
		require.Equal(ts.T(), len(expected), played)
	})

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.NotContains(ts.T(), string(stored.Resource), "password")
	require.False(ts.T(), ts.reloadUser(*stored.UserID).HasPassword())

	actions := []string{}
	for _, entry := range entries {
		payload, err := json.Marshal(entry.Payload)
		require.NoError(ts.T(), err)
		require.NotContains(ts.T(), string(payload), password)
		actions = append(actions, entry.Payload["action"].(string))
	}
	updated := string(models.SCIMUserUpdatedAction)
	require.Equal(ts.T(), []string{string(models.SCIMUserCreatedAction), updated, updated, updated}, actions)
}
