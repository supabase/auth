package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const oktaUser = `{
	"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
	"userName": "Alice@Example.com",
	"name": {"givenName": "Alice", "familyName": "Smith"},
	"emails": [{"primary": true, "value": "alice@example.com", "type": "work"}],
	"displayName": "Alice Smith",
	"locale": "en-US",
	"externalId": "00u1abcd",
	"groups": [],
	"password": "hunter2hunter2",
	"active": true
}`

type SCIMUsersTestSuite struct {
	suite.Suite
	API    *API
	TokenA string
	TokenB string
	A      *models.SSOProvider
	B      *models.SSOProvider
}

func TestSCIMUsers(t *testing.T) {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.Experimental.ScimEnabled = true
		}
	})
	require.NoError(t, err)
	defer api.db.Close()

	suite.Run(t, &SCIMUsersTestSuite{API: api})
}

func (ts *SCIMUsersTestSuite) SetupTest() {
	require.NoError(ts.T(), models.TruncateAll(ts.API.db))
	ts.A, ts.TokenA = ts.provider()
	ts.B, ts.TokenB = ts.provider()
}

func (ts *SCIMUsersTestSuite) provider() (*models.SSOProvider, string) {
	provider := &models.SSOProvider{}
	require.NoError(ts.T(), ts.API.db.Create(provider))
	_, token, err := models.CreateSCIMToken(ts.API.db, provider, nil)
	require.NoError(ts.T(), err)
	return provider, token
}

func (ts *SCIMUsersTestSuite) do(token, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	return ts.doAs(protocol.MediaType, token, method, path, body)
}

func (ts *SCIMUsersTestSuite) doAs(contentType, token, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)

	var decoded map[string]any
	if w.Body.Len() > 0 {
		require.NoError(ts.T(), json.Unmarshal(w.Body.Bytes(), &decoded), w.Body.String())
	}
	return w, decoded
}

func (ts *SCIMUsersTestSuite) create(token, body string) string {
	w, created := ts.do(token, http.MethodPost, "/Users", body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return created["id"].(string)
}

func (ts *SCIMUsersTestSuite) list(token, filter string) map[string]any {
	w, body := ts.do(token, http.MethodGet, "/Users?"+url.Values{"filter": {filter}, "startIndex": {"1"}, "count": {"100"}}.Encode(), "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return body
}

func userWith(userName, externalID string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + externalID + `"}`
}

func (ts *SCIMUsersTestSuite) TestOktaLifecycle() {
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice@example.com"`)["totalResults"])

	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Users/" + id
	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.Equal(ts.T(), location, created["meta"].(map[string]any)["location"])
	require.Equal(ts.T(), "Alice@Example.com", created["userName"])
	require.Equal(ts.T(), "00u1abcd", created["externalId"])
	require.NotContains(ts.T(), created, "displayName")
	require.NotContains(ts.T(), w.Body.String(), "hunter2")

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.Equal(ts.T(), ts.A.ID, stored.SSOProviderID)
	require.Equal(ts.T(), "alice@example.com", stored.UserName)
	require.NotContains(ts.T(), string(stored.Resource), "hunter2")
	require.NotContains(ts.T(), string(stored.Resource), `"id"`)

	for _, filter := range []string{`userName eq "alice@example.com"`, `userName eq "ALICE@EXAMPLE.COM"`, `externalId eq "00u1abcd"`} {
		found := ts.list(ts.TokenA, filter)
		require.EqualValues(ts.T(), 1, found["totalResults"], filter)
		require.Equal(ts.T(), id, found["Resources"].([]any)[0].(map[string]any)["id"], filter)
	}
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `externalId eq "00U1ABCD"`)["totalResults"])

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), "Alice", got["name"].(map[string]any)["givenName"])

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, strings.Replace(oktaUser, `"givenName": "Alice"`, `"givenName": "Alicia"`, 1))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Alicia", replaced["name"].(map[string]any)["givenName"])
	require.Equal(ts.T(), created["meta"].(map[string]any)["created"], replaced["meta"].(map[string]any)["created"])

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "value": {"active": false}}]
	}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, patched["active"])
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.False(ts.T(), stored.Active)

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	w, _ = ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNotFound, w.Code)
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice@example.com"`)["totalResults"])

	ts.create(ts.TokenA, oktaUser)
}

func (ts *SCIMUsersTestSuite) TestOktaContentTypesAndReactivate() {
	for i, contentType := range []string{"application/scim+json; charset=utf-8", "application/json", "application/json; charset=utf-8"} {
		name := string(rune('a'+i)) + "@example.com"
		w, created := ts.doAs(contentType, ts.TokenA, http.MethodPost, "/Users", userWith(name, name))
		require.Equal(ts.T(), http.StatusCreated, w.Code, contentType+" "+w.Body.String())
		id := created["id"].(string)

		for _, active := range []bool{false, true} {
			w, patched := ts.doAs(contentType, ts.TokenA, http.MethodPatch, "/Users/"+id, `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				"Operations": [{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}]
			}`)
			require.Equal(ts.T(), http.StatusOK, w.Code, contentType+" "+w.Body.String())
			require.Equal(ts.T(), active, patched["active"], contentType)
		}
	}
}

func (ts *SCIMUsersTestSuite) TestUniquenessWithinProvider() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	for _, body := range []string{userWith("ALICE@example.com", "a-2"), userWith("bob@example.com", "a-1")} {
		w, response := ts.do(ts.TokenA, http.MethodPost, "/Users", body)
		require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
		require.Equal(ts.T(), "uniqueness", response["scimType"])
	}

	ts.create(ts.TokenB, userWith("alice@example.com", "a-1"))
}

func (ts *SCIMUsersTestSuite) TestUniqueIndexIsTheBackstop() {
	ctx, err := scim.NewTokenValidator(ts.API.db)(context.Background(), ts.TokenA)
	require.NoError(ts.T(), err)
	users := scim.NewUserRepository(ts.API.config, ts.API.db)

	_, err = users.Create(ctx, &core.User{UserName: "alice@example.com"})
	require.NoError(ts.T(), err)

	_, err = users.Create(ctx, &core.User{UserName: "Alice@Example.com"})
	var scimErr *scimerrors.Error
	require.ErrorAs(ts.T(), err, &scimErr)
	require.Equal(ts.T(), http.StatusConflict, scimErr.StatusCode())
}

func (ts *SCIMUsersTestSuite) TestReplaceRejectsStaleVersion() {
	ctx, err := scim.NewTokenValidator(ts.API.db)(context.Background(), ts.TokenA)
	require.NoError(ts.T(), err)
	users := scim.NewUserRepository(ts.API.config, ts.API.db)

	created, err := users.Create(ctx, &core.User{UserName: "alice@example.com"})
	require.NoError(ts.T(), err)
	read, err := users.Get(ctx, created.ResourceID())
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), created.GetMeta().Version, read.GetMeta().Version)

	winner := &core.User{UserName: "alice@example.com", Title: "winner"}
	winner.SetID(read.ResourceID())
	winner.SetMeta(core.Meta{Version: read.GetMeta().Version})
	replaced, err := users.Replace(ctx, winner)
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), read.GetMeta().Version, replaced.GetMeta().Version)

	for _, version := range []string{read.GetMeta().Version, `W/"garbage"`} {
		loser := &core.User{UserName: "alice@example.com", Title: "loser"}
		loser.SetID(read.ResourceID())
		loser.SetMeta(core.Meta{Version: version})
		_, err = users.Replace(ctx, loser)
		var scimErr *scimerrors.Error
		require.ErrorAs(ts.T(), err, &scimErr, version)
		require.Equal(ts.T(), http.StatusPreconditionFailed, scimErr.StatusCode(), version)
	}

	missing := &core.User{UserName: "bob@example.com"}
	missing.SetID(uuid.Must(uuid.NewV4()).String())
	missing.SetMeta(core.Meta{Version: read.GetMeta().Version})
	_, err = users.Replace(ctx, missing)
	var scimErr *scimerrors.Error
	require.ErrorAs(ts.T(), err, &scimErr)
	require.Equal(ts.T(), http.StatusNotFound, scimErr.StatusCode())

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", read.ResourceID()).First(&stored))
	require.Contains(ts.T(), string(stored.Resource), "winner")
}

func (ts *SCIMUsersTestSuite) TestTenantIsolation() {
	idA := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	idB := ts.create(ts.TokenB, userWith("bob@example.com", "b-1"))

	listA := ts.list(ts.TokenA, "")
	require.EqualValues(ts.T(), 1, listA["totalResults"])
	require.Equal(ts.T(), idA, listA["Resources"].([]any)[0].(map[string]any)["id"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "bob@example.com"`)["totalResults"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `externalId eq "b-1"`)["totalResults"])

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, userWith("bob@example.com", "b-1")},
		{http.MethodPatch, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`},
		{http.MethodDelete, ""},
	} {
		w, _ := ts.do(ts.TokenA, tc.method, "/Users/"+idB, tc.body)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, tc.method)
	}

	w, got := ts.do(ts.TokenB, http.MethodGet, "/Users/"+idB, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), "bob@example.com", got["userName"])
	require.Equal(ts.T(), true, got["active"])
}

func (ts *SCIMUsersTestSuite) TestActiveDefaultsToTrue() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code)
	require.Equal(ts.T(), true, created["active"])

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+created["id"].(string), userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), true, replaced["active"])
}

func (ts *SCIMUsersTestSuite) TestPagination() {
	for _, name := range []string{"a", "b", "c"} {
		ts.create(ts.TokenA, userWith(name+"@example.com", name))
	}

	w, page := ts.do(ts.TokenA, http.MethodGet, "/Users?startIndex=2&count=1", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.EqualValues(ts.T(), 2, page["startIndex"])
	require.Len(ts.T(), page["Resources"], 1)
	require.Equal(ts.T(), "b@example.com", page["Resources"].([]any)[0].(map[string]any)["userName"])

	w, page = ts.do(ts.TokenA, http.MethodGet, "/Users?count=0", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.Empty(ts.T(), page["Resources"])

	w, page = ts.do(ts.TokenA, http.MethodGet, "/Users?startIndex=10&count=5", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.Empty(ts.T(), page["Resources"])
}

func (ts *SCIMUsersTestSuite) TestUnsupportedFilters() {
	for _, filter := range []string{
		`userName co "alice"`,
		`userName ne "alice"`,
		`name.givenName eq "Alice"`,
		`emails[value eq "alice@example.com"]`,
		`userName eq "a" or userName eq "b"`,
		`userName eq "a" and externalId eq "b"`,
		`userName pr`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+url.Values{"filter": {filter}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, filter)
		require.Equal(ts.T(), "invalidFilter", body["scimType"], filter)
	}
}

func (ts *SCIMUsersTestSuite) TestUnknownID() {
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		w, _ := ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code, id)
	}
}

func (ts *SCIMUsersTestSuite) TestRequiresSSOProviderOnContext() {
	users := scim.NewUserRepository(ts.API.config, ts.API.db)

	_, _, err := users.List(context.Background(), &protocol.SearchRequest{Count: 10})
	require.Error(ts.T(), err)
	_, err = users.Get(context.Background(), "00000000-0000-0000-0000-000000000000")
	require.Error(ts.T(), err)
}
