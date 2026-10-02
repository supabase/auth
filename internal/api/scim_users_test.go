package api

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
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

func (ts *SCIMTestSuite) create(token, body string) string {
	w, created := ts.do(token, http.MethodPost, "/Users", body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return created["id"].(string)
}

func (ts *SCIMTestSuite) list(token, filter string) map[string]any {
	w, body := ts.do(token, http.MethodGet, "/Users?"+url.Values{"filter": {filter}, "startIndex": {"1"}, "count": {"100"}}.Encode(), "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return body
}

func (ts *SCIMTestSuite) repository() (context.Context, server.Repository[*core.User]) {
	ctx, err := newSCIMTokenValidator(ts.API.db)(context.Background(), ts.TokenA)
	require.NoError(ts.T(), err)
	ctx = scimRequestKey.WithValue(ctx, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil))
	return ctx, &scimUserRepository{api: ts.API}
}

func (ts *SCIMTestSuite) TestOktaLifecycle() {
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice@example.com"`)["totalResults"])

	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Users/" + id
	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.Equal(ts.T(), location, created["meta"].(map[string]any)["location"])
	require.Equal(ts.T(), "Alice@Example.com", created["userName"])
	require.Equal(ts.T(), "00u1abcd", created["externalId"])
	require.Equal(ts.T(), "Alice Smith", created["displayName"])
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

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, oktaUserWith("givenName", "Alicia"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Alicia", replaced["name"].(map[string]any)["givenName"])
	require.Equal(ts.T(), created["meta"].(map[string]any)["created"], replaced["meta"].(map[string]any)["created"])

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "value": {"active": false}}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, patched["active"])
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.False(ts.T(), stored.Active)

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, oktaUser},
		{http.MethodPatch, patchOp(`{"op":"replace","value":{"active":true}}`)},
		{http.MethodDelete, ""},
	} {
		w, _ = ts.do(ts.TokenA, tc.method, "/Users/"+id, tc.body)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, tc.method)
	}
	for _, filter := range []string{"", `userName eq "alice@example.com"`, `externalId eq "00u1abcd"`} {
		require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, filter)["totalResults"], filter)
	}

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.NotNil(ts.T(), stored.DeletedAt)
}

func (ts *SCIMTestSuite) TestOktaContentTypesAndReactivate() {
	for i, contentType := range []string{"application/scim+json; charset=utf-8", "application/json", "application/json; charset=utf-8"} {
		name := string(rune('a'+i)) + "@example.com"
		w, created := ts.doAs(contentType, ts.TokenA, http.MethodPost, "/Users", userWith(name, name))
		require.Equal(ts.T(), http.StatusCreated, w.Code, contentType+" "+w.Body.String())
		id := created["id"].(string)

		for _, active := range []bool{false, true} {
			w, patched := ts.doAs(contentType, ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(`{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}`))
			require.Equal(ts.T(), http.StatusOK, w.Code, contentType+" "+w.Body.String())
			require.Equal(ts.T(), active, patched["active"], contentType)
		}
	}
}

func (ts *SCIMTestSuite) TestUnsupportedEndpointsReturnNotImplemented() {
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/Me"},
		{http.MethodPost, "/Bulk"},
		{http.MethodPost, "/.search"},
		{http.MethodPost, "/Users/.search"},
		{http.MethodPost, "/Groups/.search"},
	} {
		w, _ := ts.do(ts.TokenA, tc.method, tc.path, "{}")
		require.Equal(ts.T(), http.StatusNotImplemented, w.Code, tc.path)
		require.Equal(ts.T(), protocol.MediaType, w.Header().Get("Content-Type"), tc.path)
		require.Contains(ts.T(), w.Body.String(), protocol.SchemaError, tc.path)
	}
}

func (ts *SCIMTestSuite) TestUniquenessWithinProvider() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	for _, body := range []string{userWith("ALICE@example.com", "a-2"), userWith("bob@example.com", "a-1")} {
		w, response := ts.do(ts.TokenA, http.MethodPost, "/Users", body)
		require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
		require.Equal(ts.T(), "uniqueness", response["scimType"])
	}

	ts.create(ts.TokenB, userWith("alice@example.com", "a-1"))
}

func (ts *SCIMTestSuite) TestUniqueIndexIsTheBackstop() {
	ctx, users := ts.repository()

	_, err := users.Create(ctx, &core.User{UserName: "alice@example.com", Emails: emails("alice@example.com")})
	require.NoError(ts.T(), err)

	_, err = users.Create(ctx, &core.User{UserName: "Alice@Example.com", Emails: emails("alice@example.com")})
	var scimErr *scimerrors.Error
	require.ErrorAs(ts.T(), err, &scimErr)
	require.Equal(ts.T(), http.StatusConflict, scimErr.StatusCode())
}

func (ts *SCIMTestSuite) TestReplaceRejectsStaleVersion() {
	ctx, users := ts.repository()

	created, err := users.Create(ctx, &core.User{UserName: "alice@example.com", Emails: emails("alice@example.com")})
	require.NoError(ts.T(), err)
	read, err := users.Read(ctx, created.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), created.Meta.Version, read.Meta.Version)

	winner := &core.User{UserName: "alice@example.com", Title: "winner"}
	winner.ID = read.ID
	winner.Meta = core.Meta{Version: read.Meta.Version}
	replaced, err := users.Update(ctx, winner)
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), read.Meta.Version, replaced.Meta.Version)

	for _, version := range []string{read.Meta.Version, `W/"garbage"`} {
		loser := &core.User{UserName: "alice@example.com", Title: "loser"}
		loser.ID = read.ID
		loser.Meta = core.Meta{Version: version}
		_, err = users.Update(ctx, loser)
		var scimErr *scimerrors.Error
		require.ErrorAs(ts.T(), err, &scimErr, version)
		require.Equal(ts.T(), http.StatusPreconditionFailed, scimErr.StatusCode(), version)
	}

	missing := &core.User{UserName: "bob@example.com"}
	missing.ID = uuid.Must(uuid.NewV4()).String()
	missing.Meta = core.Meta{Version: read.Meta.Version}
	_, err = users.Update(ctx, missing)
	var scimErr *scimerrors.Error
	require.ErrorAs(ts.T(), err, &scimErr)
	require.Equal(ts.T(), http.StatusNotFound, scimErr.StatusCode())

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", read.ID).First(&stored))
	require.Contains(ts.T(), string(stored.Resource), "winner")
}

func (ts *SCIMTestSuite) TestDeleteRejectsStaleVersion() {
	ctx, users := ts.repository()
	target := func(id, version string) *core.User {
		user := &core.User{}
		user.ID = id
		user.Meta = core.Meta{Version: version}
		return user
	}

	created, err := users.Create(ctx, &core.User{UserName: "alice@example.com", Emails: emails("alice@example.com")})
	require.NoError(ts.T(), err)

	updated := &core.User{UserName: "alice@example.com", Title: "renamed"}
	updated.ID = created.ID
	updated.Meta = core.Meta{Version: created.Meta.Version}
	replaced, err := users.Update(ctx, updated)
	require.NoError(ts.T(), err)

	for _, version := range []string{created.Meta.Version, `W/"garbage"`} {
		err := users.Delete(ctx, target(created.ID, version))
		var scimErr *scimerrors.Error
		require.ErrorAs(ts.T(), err, &scimErr, version)
		require.Equal(ts.T(), http.StatusPreconditionFailed, scimErr.StatusCode(), version)
	}

	var stored models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", created.ID).First(&stored))
	require.Nil(ts.T(), stored.DeletedAt)

	missing := uuid.Must(uuid.NewV4()).String()
	var scimErr *scimerrors.Error
	err = users.Delete(ctx, target(missing, ""))
	require.ErrorAs(ts.T(), err, &scimErr)
	require.Equal(ts.T(), http.StatusNotFound, scimErr.StatusCode())

	require.NoError(ts.T(), users.Delete(ctx, target(created.ID, replaced.Meta.Version)))
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", created.ID).First(&stored))
	require.NotNil(ts.T(), stored.DeletedAt)
}

func (ts *SCIMTestSuite) whileLocked(lock, finish func(tx *storage.Connection) error, method, path, body string, headers ...string) (int, error) {
	locked, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- ts.API.db.Transaction(func(tx *storage.Connection) error {
			err := lock(tx)
			close(locked)
			if err != nil {
				return err
			}
			<-release
			return finish(tx)
		})
	}()
	<-locked

	code := make(chan int, 1)
	go func() {
		code <- ts.serve(protocol.MediaType, ts.TokenA, method, path, body, headers...).Code
	}()
	select {
	case c := <-code:
		ts.T().Fatalf("%s %s finished while the lock was held: %d", method, path, c)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	return <-code, <-held
}

func (ts *SCIMTestSuite) scimAuditEntries() []models.AuditLogEntry {
	return queryAuditEntries(ts.T(), ts.API.db, "payload->>'log_type' = ?", "scim")
}

func (ts *SCIMTestSuite) auditDuring(fn func()) []models.AuditLogEntry {
	before := len(ts.scimAuditEntries())
	fn()
	return ts.scimAuditEntries()[before:]
}

func (ts *SCIMTestSuite) TestAuditLog() {
	id := ts.create(ts.TokenA, oktaUser)

	w, _ := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())

	for _, operation := range []string{
		`{"op":"replace","path":"displayName","value":"Alice S."}`,
		`{"op":"replace","path":"active","value":false}`,
		`{"op":"replace","path":"active","value":true}`,
	} {
		w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patchOp(operation))
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	}

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())

	tokens, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)
	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))

	actions := []string{}
	for _, entry := range ts.scimAuditEntries() {
		actions = append(actions, entry.Payload["action"].(string))
		require.Equal(ts.T(), uuid.Nil.String(), entry.Payload["actor_id"])
		require.Equal(ts.T(), "scim:"+tokens[0].Prefix, entry.Payload["actor_username"])
		traits := entry.Payload["traits"].(map[string]any)
		require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"])
		require.Equal(ts.T(), id, traits["scim_user_id"])
		require.Equal(ts.T(), row.UserID.String(), traits["user_id"])
		require.Equal(ts.T(), "success", traits["outcome"])
	}
	require.Equal(ts.T(), []string{
		string(models.SCIMUserCreatedAction),
		string(models.SCIMUserUpdatedAction),
		string(models.SCIMUserUpdatedAction),
		string(models.SCIMUserUpdatedAction),
		string(models.SCIMUserDeletedAction),
	}, actions)
}

func (ts *SCIMTestSuite) TestRolesRoundTrip() {
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","emails":[{"primary":true,"value":"alice@example.com"}],"roles":[{"value":"admin","primary":true},{"value":"billing"}]}`
	id := ts.create(ts.TokenA, body)

	w, read := ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	roles := []string{}
	for _, role := range read["roles"].([]any) {
		roles = append(roles, role.(map[string]any)["value"].(string))
	}
	require.Equal(ts.T(), []string{"admin", "billing"}, roles)
}

func (ts *SCIMTestSuite) TestConcurrentCreateWithinProvider() {
	const attempts = 8
	codes := make(chan int, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start
			codes <- ts.serve(protocol.MediaType, ts.TokenA, http.MethodPost, "/Users", userWith("race@example.com", "")).Code
		})
	}
	close(start)
	wg.Wait()
	close(codes)

	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	require.Equal(ts.T(), map[int]int{http.StatusCreated: 1, http.StatusConflict: attempts - 1}, counts)
	require.EqualValues(ts.T(), 1, ts.list(ts.TokenA, `userName eq "race@example.com"`)["totalResults"])
}

func (ts *SCIMTestSuite) TestSort() {
	ids := map[string]string{}
	for _, name := range []string{"carol@example.com", "Alice@example.com", "bob@example.com"} {
		ids[name] = ts.create(ts.TokenA, userWith(name, name))
	}
	ts.create(ts.TokenB, userWith("aaron@example.com", "b"))

	sorted := func(params url.Values) []string {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+params.Encode(), "")
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		names := []string{}
		for _, resource := range body["Resources"].([]any) {
			names = append(names, resource.(map[string]any)["userName"].(string))
		}
		return names
	}

	require.Equal(ts.T(), []string{"Alice@example.com", "bob@example.com", "carol@example.com"}, sorted(url.Values{"sortBy": {"userName"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "bob@example.com", "Alice@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "sortOrder": {"descending"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "Alice@example.com", "bob@example.com"}, sorted(url.Values{"sortBy": {"meta.created"}}))
	require.Equal(ts.T(), []string{"carol@example.com", "Alice@example.com", "bob@example.com"}, sorted(url.Values{"sortOrder": {"descending"}}))
	require.Equal(ts.T(), []string{"Alice@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "count": {"1"}}))
	require.Equal(ts.T(), []string{"bob@example.com"}, sorted(url.Values{"sortBy": {"userName"}, "startIndex": {"2"}, "count": {"1"}}))

	_, body := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+ids["carol@example.com"], patchOp(`{"op":"replace","path":"title","value":"Lead"}`))
	require.Equal(ts.T(), "Lead", body["title"])
	require.Equal(ts.T(), "carol@example.com", sorted(url.Values{"sortBy": {"meta.lastModified"}, "sortOrder": {"descending"}})[0])

	byID := sorted(url.Values{"sortBy": {"id"}})
	require.Len(ts.T(), byID, 3)
	expected := []string{ids["carol@example.com"], ids["Alice@example.com"], ids["bob@example.com"]}
	slices.Sort(expected)
	names := map[string]string{}
	for name, id := range ids {
		names[id] = name
	}
	require.Equal(ts.T(), []string{names[expected[0]], names[expected[1]], names[expected[2]]}, byID)

	for _, sortBy := range []string{"displayName", "emails.value", "password"} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+url.Values{"sortBy": {sortBy}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, sortBy)
		require.Equal(ts.T(), string(scimerrors.InvalidValue), body["scimType"], sortBy)
	}
}

func (ts *SCIMTestSuite) TestAttributeProjection() {
	id := ts.create(ts.TokenA, oktaUser)

	for _, path := range []string{"/Users/" + id, "/Users"} {
		w, body := ts.do(ts.TokenA, http.MethodGet, path+"?attributes=userName", "")
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		user := body
		if path == "/Users" {
			user = body["Resources"].([]any)[0].(map[string]any)
		}
		require.Equal(ts.T(), "Alice@Example.com", user["userName"])
		require.Equal(ts.T(), id, user["id"])
		require.NotNil(ts.T(), user["schemas"])
		require.NotContains(ts.T(), user, "meta")
		require.NotContains(ts.T(), user, "displayName")
		require.NotContains(ts.T(), user, "emails")

		w, body = ts.do(ts.TokenA, http.MethodGet, path+"?excludedAttributes=displayName,emails", "")
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		user = body
		if path == "/Users" {
			user = body["Resources"].([]any)[0].(map[string]any)
		}
		require.Equal(ts.T(), "Alice@Example.com", user["userName"])
		require.NotContains(ts.T(), user, "displayName")
		require.NotContains(ts.T(), user, "emails")
		require.Contains(ts.T(), user, "name")

		w, body = ts.do(ts.TokenA, http.MethodGet, path+"?attributes=userName&excludedAttributes=emails", "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
		require.Equal(ts.T(), string(scimerrors.InvalidValue), body["scimType"])
	}
}

func (ts *SCIMTestSuite) TestWriteResponseProjection() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users?attributes=userName", userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	require.ElementsMatch(ts.T(), []string{"id", "schemas", "userName"}, slices.Collect(maps.Keys(created)))

	w, got := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id+"?excludedAttributes=emails", userWith("alice@example.com", "a-2"))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "emails")
	require.Equal(ts.T(), "a-2", got["externalId"])

	w, got = ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id+"?excludedAttributes=emails", patchOp(`{"op":"replace","path":"externalId","value":"a-3"}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "emails")
	require.Equal(ts.T(), "a-3", got["externalId"])

	group := ts.createGroup(ts.TokenA, groupWith("Engineering", ""))
	w, got = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+group+"?attributes=displayName", patchOp(`{"op":"add","path":"members","value":[{"value":"`+id+`"}]}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{"id", "schemas", "displayName"}, slices.Collect(maps.Keys(got)))

	w, got = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+group, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{id}, memberValues(got))
}

func (ts *SCIMTestSuite) TestETagAndIfMatch() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", oktaUser)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	stale := w.Header().Get("ETag")
	require.NotEmpty(ts.T(), stale)
	require.Equal(ts.T(), created["meta"].(map[string]any)["version"], stale)

	w, _ = ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), stale, w.Header().Get("ETag"))

	patch := patchOp(`{"op":"replace","path":"displayName","value":"Alice S."}`)
	w, patched := ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Users/"+id, patch, "If-Match", stale)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Alice S.", patched["displayName"])
	current := w.Header().Get("ETag")
	require.NotEqual(ts.T(), stale, current)

	for _, tc := range []struct{ method, body string }{
		{http.MethodPut, oktaUser},
		{http.MethodPatch, patch},
		{http.MethodDelete, ""},
	} {
		w, _ := ts.doAs(protocol.MediaType, ts.TokenA, tc.method, "/Users/"+id, tc.body, "If-Match", stale)
		require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, tc.method+" "+w.Body.String())
	}

	w, replaced := ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, "/Users/"+id, oktaUser, "If-Match", current)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Alice Smith", replaced["displayName"])

	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodDelete, "/Users/"+id, "", "If-Match", w.Header().Get("ETag"))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) TestPatchAttributesOutsideTheMinimalSchema() {
	id := ts.create(ts.TokenA, oktaUser)

	patch := patchOp(`{"op":"replace","path":"title","value":"Engineer"}`, `{"op":"add","path":"phoneNumbers","value":[{"value":"555-0100","type":"work"}]}`, `{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Auth"}`)
	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, patch)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Engineer", patched["title"])

	w, read := ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), "Engineer", read["title"])
	require.Equal(ts.T(), "555-0100", read["phoneNumbers"].([]any)[0].(map[string]any)["value"])
	require.Equal(ts.T(), "Auth", read[string(core.SchemaEnterpriseUser)].(map[string]any)["department"])
	require.ElementsMatch(ts.T(), []any{string(core.SchemaUser), string(core.SchemaEnterpriseUser)}, read["schemas"])
}

func (ts *SCIMTestSuite) TestActiveDefaultsToTrue() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code)
	require.Equal(ts.T(), true, created["active"])

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+created["id"].(string), userWith("alice@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), true, replaced["active"])
}

func (ts *SCIMTestSuite) TestPagination() {
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

	w, page = ts.do(ts.TokenA, http.MethodGet, "/Users?startIndex=2&count=5", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.Len(ts.T(), page["Resources"], 2)
}

func (ts *SCIMTestSuite) TestPageSizeCap() {
	for i := range 101 {
		_, err := models.CreateSCIMUser(ts.API.db, ts.A.ID, []byte(`{"userName":"user`+strconv.Itoa(i)+`@example.com"}`))
		require.NoError(ts.T(), err)
	}

	for _, query := range []string{"", "?count=200"} {
		w, page := ts.do(ts.TokenA, http.MethodGet, "/Users"+query, "")
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		require.Equal(ts.T(), []any{string(protocol.SchemaListResponse)}, page["schemas"], query)
		require.EqualValues(ts.T(), 101, page["totalResults"], query)
		require.EqualValues(ts.T(), 1, page["startIndex"], query)
		require.EqualValues(ts.T(), 100, page["itemsPerPage"], query)
		require.Len(ts.T(), page["Resources"], 100, query)
	}
}

func (ts *SCIMTestSuite) TestSortTieBreaksOnID() {
	ids := []string{
		ts.create(ts.TokenA, userWith("alice@example.com", "a-1")),
		ts.create(ts.TokenA, userWith("bob@example.com", "b-1")),
		ts.create(ts.TokenA, userWith("carol@example.com", "c-1")),
	}
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"UPDATE "+(&models.SCIMUser{}).TableName()+" SET created_at = '2026-01-01T00:00:00Z', updated_at = '2026-01-01T00:00:00Z' WHERE sso_provider_id = ?", ts.A.ID,
	).Exec())
	slices.Sort(ids)
	descending := slices.Clone(ids)
	slices.Reverse(descending)

	for _, sortBy := range []string{"meta.created", "meta.lastModified"} {
		for order, want := range map[string][]string{"ascending": ids, "descending": descending} {
			got := []string{}
			for startIndex := 1; startIndex <= len(ids); startIndex++ {
				params := url.Values{"sortBy": {sortBy}, "sortOrder": {order}, "startIndex": {strconv.Itoa(startIndex)}, "count": {"1"}}
				w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+params.Encode(), "")
				require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
				got = append(got, body["Resources"].([]any)[0].(map[string]any)["id"].(string))
			}
			require.Equal(ts.T(), want, got, sortBy+" "+order)
		}
	}
}

func (ts *SCIMTestSuite) TestUnsupportedFilters() {
	for _, filter := range []string{
		`userName co "alice"`,
		`userName ne "alice"`,
		`name.givenName eq "Alice"`,
		`emails[value eq "alice@example.com"]`,
		`userName eq "a" or userName eq "b"`,
		`userName eq "a" and externalId eq "b"`,
		`userName pr`,
		`not (userName eq "a")`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Users?"+url.Values{"filter": {filter}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, filter)
		require.Equal(ts.T(), "invalidFilter", body["scimType"], filter)
	}
}

func (ts *SCIMTestSuite) TestUnknownID() {
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		w, _ := ts.do(ts.TokenA, http.MethodGet, "/Users/"+id, "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code, id)
	}
}

func (ts *SCIMTestSuite) TestRequiresSSOProviderOnContext() {
	users := &scimUserRepository{api: ts.API}

	_, _, err := users.List(context.Background(), &protocol.SearchRequest{Count: 10})
	require.Error(ts.T(), err)
	_, err = users.Read(context.Background(), "00000000-0000-0000-0000-000000000000")
	require.Error(ts.T(), err)
}

func (ts *SCIMTestSuite) TestPrimaryEmailRequiredToProvision() {
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"not-an-email"}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(ts.T(), body["detail"], "is required")
}

func (ts *SCIMTestSuite) TestPrimaryEmailPrefersThePrimaryFlag() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dana@example.com","emails":[{"value":"work@example.com"},{"value":"home@example.com","primary":true}]}`)
	require.Equal(ts.T(), "home@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestPrimaryEmailFallsBackToTheFirstEmail() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"erin@example.com","emails":[{"value":"work@example.com"},{"value":"home@example.com"}]}`)
	require.Equal(ts.T(), "work@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMTestSuite) TestUsersGroupsAttribute() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	ops := ts.createGroup(ts.TokenA, groupWith("Ops", "g-2", alice))
	eng := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))

	groupsOf := func(user map[string]any) []map[string]any {
		found := []map[string]any{}
		groups, _ := user["groups"].([]any)
		for _, group := range groups {
			found = append(found, group.(map[string]any))
		}
		return found
	}
	storedResource := func(id string) string {
		var stored models.SCIMUser
		require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
		return string(stored.Resource)
	}

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []map[string]any{
		{"value": eng, "$ref": "http://localhost:9999/scim/v2/Groups/" + eng, "display": "Engineering", "type": "direct"},
		{"value": ops, "$ref": "http://localhost:9999/scim/v2/Groups/" + ops, "display": "Ops", "type": "direct"},
	}, groupsOf(got))

	w, got = ts.do(ts.TokenA, http.MethodGet, "/Users/"+bob, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), got, "groups")

	listed := ts.list(ts.TokenA, `userName eq "alice@example.com"`)
	require.Len(ts.T(), groupsOf(listed["Resources"].([]any)[0].(map[string]any)), 2)

	claimed := `[{"value":"` + ops + `","display":"Forged"}]`
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol@example.com","emails":[{"primary":true,"value":"carol@example.com"}],"groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(ts.T(), created, "groups")
	require.NotContains(ts.T(), storedResource(created["id"].(string)), "groups")

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Users/"+bob, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com","groups":`+claimed+`}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.NotContains(ts.T(), replaced, "groups")
	require.NotContains(ts.T(), storedResource(bob), "groups")

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+alice, patchOp(`{"op":"replace","path":"displayName","value":"Alice"}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), groupsOf(patched), 2)
	require.NotContains(ts.T(), storedResource(alice), "groups")

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+ops, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	w, got = ts.do(ts.TokenA, http.MethodGet, "/Users/"+alice, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), groupsOf(got), 1)
	require.Equal(ts.T(), eng, groupsOf(got)[0]["value"])
}

func userWith(userName, externalID string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + externalID + `","emails":[{"primary":true,"value":"` + userName + `"}]}`
}

func emails(value string) []core.Email {
	return []core.Email{{Value: value, Primary: new(true)}}
}

func oktaUserWith(field string, value any) string {
	return withField(oktaUser, field, value)
}

func withField(body, field string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	match := regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `": ("[^"]*"|true|false)`).FindStringIndex(body)
	if match == nil {
		panic("no " + field + " in body")
	}
	return body[:match[0]] + `"` + field + `": ` + string(encoded) + body[match[1]:]
}

func patchOp(ops ...string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` + strings.Join(ops, ",") + `]}`
}
