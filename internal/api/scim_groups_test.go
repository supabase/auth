package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gofrs/uuid"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func groupWith(displayName, externalID string, memberIDs ...string) string {
	members := make([]string, len(memberIDs))
	for i, id := range memberIDs {
		members[i] = `{"value":"` + id + `"}`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"` + displayName + `","externalId":"` + externalID + `","members":[` + strings.Join(members, ",") + `]}`
}

func (ts *SCIMTestSuite) createGroup(token, body string) string {
	w, created := ts.do(token, http.MethodPost, "/Groups", body)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	return created["id"].(string)
}

func (ts *SCIMTestSuite) listGroups(token, filter string) map[string]any {
	w, body := ts.do(token, http.MethodGet, "/Groups?"+url.Values{"filter": {filter}}.Encode(), "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return body
}

func memberValues(group map[string]any) []string {
	values := []string{}
	members, _ := group["members"].([]any)
	for _, member := range members {
		values = append(values, member.(map[string]any)["value"].(string))
	}
	return values
}

func addMembers(ids ...string) string {
	values := make([]string, len(ids))
	for i, id := range ids {
		values[i] = `{"value":"` + id + `"}`
	}
	return `{"op":"add","path":"members","value":[` + strings.Join(values, ",") + `]}`
}

func removeMember(id string) string {
	return `{"op":"remove","path":"members[value eq \"` + id + `\"]"}`
}

func actionsOf(entries []models.AuditLogEntry) []string {
	actions := []string{}
	for _, entry := range entries {
		actions = append(actions, entry.Payload["action"].(string))
	}
	return actions
}

func (ts *SCIMTestSuite) etag(path string) string {
	w, _ := ts.do(ts.TokenA, http.MethodGet, path, "")
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	return w.Header().Get("ETag")
}

func (ts *SCIMTestSuite) TestGroupsLifecycle() {
	alice := ts.create(ts.TokenA, userWith("Alice@Example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))

	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "Finance", alice))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	location := "http://localhost:9999/scim/v2/Groups/" + id
	require.Equal(ts.T(), location, w.Header().Get("Location"))
	require.NotEmpty(ts.T(), w.Header().Get("ETag"))
	require.Equal(ts.T(), "Engineering", created["displayName"])
	require.Equal(ts.T(), "Finance", created["externalId"])
	meta := created["meta"].(map[string]any)
	require.Equal(ts.T(), "Group", meta["resourceType"])
	require.Equal(ts.T(), location, meta["location"])
	member := created["members"].([]any)[0].(map[string]any)
	require.Equal(ts.T(), alice, member["value"])
	require.Equal(ts.T(), "User", member["type"])
	require.NotContains(ts.T(), member, "display")
	require.Equal(ts.T(), "http://localhost:9999/scim/v2/Users/"+alice, member["$ref"])

	var stored models.SCIMGroup
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&stored))
	require.Equal(ts.T(), ts.A.ID, stored.SSOProviderID)
	require.NotContains(ts.T(), string(stored.Resource), "members")
	require.NotContains(ts.T(), string(stored.Resource), `"id"`)

	for _, filter := range []string{`displayName eq "Engineering"`, `displayName eq "engineering"`, `externalId eq "Finance"`, `displayName eq "Engineering" and externalId eq "Finance"`, `displayName eq "Nobody" or externalId eq "Finance"`} {
		found := ts.listGroups(ts.TokenA, filter)
		require.EqualValues(ts.T(), 1, found["totalResults"], filter)
		require.Equal(ts.T(), id, found["Resources"].([]any)[0].(map[string]any)["id"], filter)
	}

	w, replaced := ts.do(ts.TokenA, http.MethodPut, "/Groups/"+id, groupWith("Engineering", "Finance", bob))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), []string{bob}, memberValues(replaced))
	require.Equal(ts.T(), meta["created"], replaced["meta"].(map[string]any)["created"])

	w, patched := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(addMembers(alice), `{"op":"replace","path":"displayName","value":"Platform"}`))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(patched))
	require.Equal(ts.T(), "Platform", patched["displayName"])

	patched = ts.patchMembers(id, removeMember(bob))
	require.Equal(ts.T(), []string{alice}, memberValues(patched))
	require.Equal(ts.T(), "Platform", patched["displayName"])

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	for _, missing := range []string{id, "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		w, _ = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+missing, "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code, missing)
	}
	ts.get(ts.TokenA, "/Users/"+alice)
}

func (ts *SCIMTestSuite) TestGroupsWithoutMembers() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Empty"}`)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(ts.T(), created, "members")

	ts.createGroup(ts.TokenA, groupWith("Empty", "e-2"))
	require.EqualValues(ts.T(), 2, ts.listGroups(ts.TokenA, `displayName eq "Empty"`)["totalResults"])
}

func (ts *SCIMTestSuite) TestGroupsRejectInvalidMembers() {
	outsider := ts.create(ts.TokenB, userWith("mallory@example.com", "m-1"))
	deleted := ts.create(ts.TokenA, userWith("gone@example.com", "g-1"))
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+deleted, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	existing := ts.createGroup(ts.TokenA, groupWith("Existing", ""))
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	for name, body := range map[string]string{
		"other provider": groupWith("Engineering", "", outsider),
		"deleted user":   groupWith("Engineering", "", deleted),
		"unknown id":     groupWith("Engineering", "", "00000000-0000-0000-0000-000000000000"),
		"not a uuid":     groupWith("Engineering", "", "alice"),
		"nested group":   `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"00000000-0000-0000-0000-000000000000","type":"Group"}]}`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodPost, "/Groups", body)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, name+" "+w.Body.String())
		require.Equal(ts.T(), "invalidValue", body["scimType"], name)
	}
	w, _ = ts.do(ts.TokenA, http.MethodPut, "/Groups/"+existing, groupWith("Existing", "", outsider))
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.EqualValues(ts.T(), 1, ts.listGroups(ts.TokenA, "")["totalResults"])
	for _, entry := range hook.AllEntries() {
		require.NotEqual(ts.T(), "audit_event", entry.Message, entry.Data)
	}
}

func (ts *SCIMTestSuite) TestGroupsMemberTypeIsCaseInsensitive() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	for _, kind := range []string{"user", "USER", "User"} {
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering %s","members":[{"value":%q,"type":%q}]}`, kind, alice, kind)
		w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", body)
		require.Equal(ts.T(), http.StatusCreated, w.Code, kind+" "+w.Body.String())
		require.Equal(ts.T(), []string{alice}, memberValues(created), kind)
	}
}

func (ts *SCIMTestSuite) TestPatchReplaceMembers() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	carol := ts.create(ts.TokenA, userWith("carol@example.com", "c-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice, bob))
	entries := ts.auditDuring(func() {
		w, got := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(`{"op":"replace","path":"members","value":[{"value":"`+bob+`"},{"value":"`+carol+`"}]}`))
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		require.ElementsMatch(ts.T(), []string{bob, carol}, memberValues(got))
	})
	require.Equal(ts.T(), []string{string(models.SCIMGroupUpdatedAction)}, actionsOf(entries))
}

func (ts *SCIMTestSuite) TestExcludedMembersKeepsWrites() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	carol := ts.create(ts.TokenA, userWith("carol@example.com", "c-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice, bob))

	got := ts.get(ts.TokenA, "/Groups/"+id+"?excludedAttributes=members")
	require.NotContains(ts.T(), got, "members")
	require.Equal(ts.T(), "Engineering", got["displayName"])
	require.NotContains(ts.T(), ts.get(ts.TokenA, "/Groups?excludedAttributes=members")["Resources"].([]any)[0], "members")
	require.NotContains(ts.T(), ts.get(ts.TokenA, "/Users/"+alice+"?excludedAttributes=groups"), "groups")

	w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id+"?excludedAttributes=members", patchOp(addMembers(carol)))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	w, _ = ts.do(ts.TokenA, http.MethodPut, "/Groups/"+id+"?excludedAttributes=members", groupWith("Platform", "", alice, bob, carol))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	got = ts.get(ts.TokenA, "/Groups/"+id)
	require.ElementsMatch(ts.T(), []string{alice, bob, carol}, memberValues(got))
	require.Equal(ts.T(), "Platform", got["displayName"])
}

func (ts *SCIMTestSuite) TestPatchRemoveAbsentMember() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice))
	require.Empty(ts.T(), ts.auditDuring(func() {
		require.Equal(ts.T(), []string{alice}, memberValues(ts.patchMembers(id, removeMember(bob))))
	}))
}

func (ts *SCIMTestSuite) TestPatchRejectsRemoveWithValue() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice, bob))

	for path, body := range map[string]string{
		"/Groups/" + id:   `{"op":"Remove","path":"members","value":[{"$ref":null,"value":"` + bob + `"}]}`,
		"/Users/" + alice: `{"op":"remove","path":"emails","value":[{"value":"alice@example.com"}]}`,
	} {
		w, got := ts.do(ts.TokenA, http.MethodPatch, path, patchOp(body))
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, path+" "+w.Body.String())
		require.Equal(ts.T(), "invalidSyntax", got["scimType"], path)
	}

	require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(ts.get(ts.TokenA, "/Groups/"+id)))
	require.NotEmpty(ts.T(), ts.get(ts.TokenA, "/Users/"+alice)["emails"])
	got := ts.patchMembers(id, `{"op":"remove","path":"members[value eq \"`+bob+`\"]","value":null}`)
	require.Equal(ts.T(), []string{alice}, memberValues(got))
}

func (ts *SCIMTestSuite) TestGroupsExternalIDUniqueWithinProvider() {
	ts.createGroup(ts.TokenA, groupWith("A", "g-1"))

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("B", "g-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])

	ts.createGroup(ts.TokenB, groupWith("A", "g-1"))
}

func (ts *SCIMTestSuite) TestGroupsETagAndIfMatch() {
	w, created := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "g-1"))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	id := created["id"].(string)
	stale := w.Header().Get("ETag")

	patch := patchOp(`{"op":"replace","path":"displayName","value":"Platform"}`)
	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Groups/"+id, patch, "If-Match", stale)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	current := w.Header().Get("ETag")
	require.NotEqual(ts.T(), stale, current)

	for _, tc := range []struct{ method, body string }{
		{http.MethodPut, groupWith("Engineering", "g-1")},
		{http.MethodPatch, patch},
		{http.MethodDelete, ""},
	} {
		w, _ := ts.doAs(protocol.MediaType, ts.TokenA, tc.method, "/Groups/"+id, tc.body, "If-Match", stale)
		require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, tc.method+" "+w.Body.String())
	}

	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodDelete, "/Groups/"+id, "", "If-Match", current)
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) TestIdenticalPutChecksIfMatch() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	for path, body := range map[string]string{
		"/Users/" + alice: userWith("alice@example.com", "a-2"),
		"/Groups/" + ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice)): groupWith("Engineering", "g-2", alice),
	} {
		stale := ts.etag(path)
		w, _ := ts.do(ts.TokenA, http.MethodPut, path, body)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		current := w.Header().Get("ETag")
		require.NotEqual(ts.T(), stale, current, path)
		events := len(ts.scimAuditEntries())

		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, path, body, "If-Match", stale)
		require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, path+" "+w.Body.String())

		w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, path, body, "If-Match", current)
		require.Equal(ts.T(), http.StatusOK, w.Code, path+" "+w.Body.String())
		require.Equal(ts.T(), current, w.Header().Get("ETag"), path)
		require.Len(ts.T(), ts.scimAuditEntries(), events, path)
	}
}

func (ts *SCIMTestSuite) TestGroupsRemoveDeletedMembers() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	eng := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice, bob))
	ops := ts.createGroup(ts.TokenA, groupWith("Ops", "g-2", alice))
	entries := ts.auditDuring(func() {
		w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+alice, "")
		require.Equal(ts.T(), http.StatusNoContent, w.Code)

		require.Equal(ts.T(), []string{bob}, memberValues(ts.get(ts.TokenA, "/Groups/"+eng)))
		require.Empty(ts.T(), memberValues(ts.get(ts.TokenA, "/Groups/"+ops)))
		require.Zero(ts.T(), ts.countRows(&models.SCIMGroupMember{}, "scim_user_id = ?", alice))
	})
	require.Equal(ts.T(), []string{string(models.SCIMUserDeletedAction)}, actionsOf(entries))
}

func (ts *SCIMTestSuite) TestGroupsVersionChangesOnMemberOnlyWrite() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
	stale := ts.etag("/Groups/" + id)

	var current string
	entries := ts.auditDuring(func() {
		w, got := ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, "/Groups/"+id, groupWith("Engineering", "g-1", bob), "If-Match", stale)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		require.Equal(ts.T(), []string{bob}, memberValues(got))
		current = w.Header().Get("ETag")
	})
	require.NotEqual(ts.T(), stale, current)
	require.Equal(ts.T(), []string{string(models.SCIMGroupUpdatedAction)}, actionsOf(entries))
	require.Equal(ts.T(), current, ts.etag("/Groups/"+id))
	w, _ := ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPut, "/Groups/"+id, groupWith("Engineering", "g-1", alice), "If-Match", stale)
	require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) TestGroupsKeepDeactivatedMembers() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
	entries := ts.auditDuring(func() {
		w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Users/"+alice, patchOp(`{"op":"replace","path":"active","value":false}`))
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

		require.ElementsMatch(ts.T(), []string{alice, bob}, memberValues(ts.patchMembers(id, addMembers(bob))))
		user := ts.get(ts.TokenA, "/Users/"+alice)
		require.Equal(ts.T(), false, user["active"])
		require.Len(ts.T(), user["groups"], 1)
	})

	require.Len(ts.T(), entries, 2)
	require.Equal(ts.T(), string(models.SCIMGroupUpdatedAction), entries[1].Payload["action"])
}

func (ts *SCIMTestSuite) TestGroupsSortAndPaginate() {
	ts.createGroup(ts.TokenA, groupWith("beta", "g-2"))
	ts.createGroup(ts.TokenA, groupWith("Alpha", "g-1"))
	ts.createGroup(ts.TokenA, groupWith("gamma", "g-3"))

	page := ts.get(ts.TokenA, "/Groups?sortBy=displayName&startIndex=2&count=1")
	require.EqualValues(ts.T(), 3, page["totalResults"])
	require.Equal(ts.T(), "beta", page["Resources"].([]any)[0].(map[string]any)["displayName"])
	page = ts.get(ts.TokenA, "/Groups?sortBy=displayName&sortOrder=descending")
	require.Equal(ts.T(), "gamma", page["Resources"].([]any)[0].(map[string]any)["displayName"])

	w, body := ts.do(ts.TokenA, http.MethodGet, "/Groups?sortBy=members.value", "")
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
}

func (ts *SCIMTestSuite) TestGroupsUnsupportedFilters() {
	for _, filter := range []string{
		`displayName co "eng"`,
		`members.value eq "00000000-0000-0000-0000-000000000000"`,
		`members[value eq "00000000-0000-0000-0000-000000000000"]`,
		`displayName pr`,
		`id eq "00000000-0000-0000-0000-000000000000"`,
	} {
		w, body := ts.do(ts.TokenA, http.MethodGet, "/Groups?"+url.Values{"filter": {filter}}.Encode(), "")
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, filter)
		require.Equal(ts.T(), "invalidFilter", body["scimType"], filter)
	}
}

func (ts *SCIMTestSuite) TestGroupsAuditLog() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	var id string
	entries := ts.auditDuring(func() {
		id = ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))

		w, _ := ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Engineering", "g-1"))
		require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
		w, _ = ts.do(ts.TokenA, http.MethodPost, "/Groups", groupWith("Invalid", "g-2", uuid.Must(uuid.NewV4()).String()))
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())

		w, _ = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(addMembers(bob), removeMember(alice), `{"op":"replace","path":"displayName","value":"Platform"}`))
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

		w, _ = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(`{"op":"replace","path":"displayName","value":"Rejected"}`, addMembers(uuid.Must(uuid.NewV4()).String())))
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())

		w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+id, "")
		require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	})

	tokens, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)

	type event struct {
		action, displayName string
	}
	events := []event{}
	for _, entry := range entries {
		require.Equal(ts.T(), uuid.Nil.String(), entry.Payload["actor_id"])
		require.Equal(ts.T(), "scim:"+tokens[0].Prefix, entry.Payload["actor_username"])
		traits := entry.Payload["traits"].(map[string]any)
		require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"])
		require.Equal(ts.T(), id, traits["scim_group_id"])
		require.Equal(ts.T(), "success", traits["outcome"])
		events = append(events, event{entry.Payload["action"].(string), traits["display_name"].(string)})
	}
	require.Equal(ts.T(), []event{
		{string(models.SCIMGroupCreatedAction), "Engineering"},
		{string(models.SCIMGroupUpdatedAction), "Platform"},
		{string(models.SCIMGroupDeletedAction), "Platform"},
	}, events)
}

func (ts *SCIMTestSuite) TestGroupsPushReplay() {
	bjensen := ts.create(ts.TokenA, userWith("bjensen@example.com", "bjensen"))
	jsmith := ts.create(ts.TokenA, userWith("jsmith@example.com", "701984"))

	type state struct {
		displayName   string
		members       []string
		bjensenActive bool
	}
	expected := map[string]state{
		"push group":                          {"Tour Guides", []string{}, true},
		"add bjensen (sent twice)":            {"Tour Guides", []string{bjensen}, true},
		"retry: bjensen and jsmith":           {"Tour Guides", []string{bjensen, jsmith}, true},
		"remove bjensen":                      {"Tour Guides", []string{jsmith}, true},
		"remove jsmith":                       {"Tour Guides", []string{}, true},
		"rename":                              {"Group A", []string{}, true},
		"re-add bjensen (sent twice)":         {"Group A", []string{bjensen}, true},
		"deactivate bjensen":                  {"Group A", []string{bjensen}, false},
		"reactivate bjensen and reassign app": {"Group A", []string{bjensen}, true},
	}
	type sent struct {
		body    string
		version any
	}
	last := map[string]sent{}
	onRequest := func(step string, request replayRequest, got map[string]any, _ string) {
		version := got["meta"].(map[string]any)["version"]
		if prev, ok := last[request.Path]; ok && request.Method == http.MethodPut && prev.body == string(request.Body) {
			require.Equal(ts.T(), prev.version, version, step)
		}
		last[request.Path] = sent{string(request.Body), version}
	}
	entries := ts.auditDuring(func() {
		played := ts.replay("okta_group_push.json", rfcGroup, []string{rfcBjensen, bjensen, rfcJsmith, jsmith}, onRequest, func(step, group string) {
			want, ok := expected[step]
			require.True(ts.T(), ok, step)
			ts.requireGroup(step, group, want.displayName, want.members)
			require.Equal(ts.T(), want.bjensenActive, ts.get(ts.TokenA, "/Users/"+bjensen)["active"], step)
		})
		require.Equal(ts.T(), len(expected), played)
	})

	type event struct {
		action, subject string
	}
	events := []event{}
	for _, entry := range entries {
		traits := entry.Payload["traits"].(map[string]any)
		subject, _ := traits["scim_user_id"].(string)
		if name, ok := traits["display_name"].(string); ok {
			subject = name
		}
		events = append(events, event{entry.Payload["action"].(string), subject})
	}
	require.Equal(ts.T(), []event{
		{string(models.SCIMGroupCreatedAction), "Tour Guides"},
		{string(models.SCIMGroupUpdatedAction), "Tour Guides"},
		{string(models.SCIMGroupUpdatedAction), "Tour Guides"},
		{string(models.SCIMGroupUpdatedAction), "Tour Guides"},
		{string(models.SCIMGroupUpdatedAction), "Tour Guides"},
		{string(models.SCIMGroupUpdatedAction), "Group A"},
		{string(models.SCIMGroupUpdatedAction), "Group A"},
		{string(models.SCIMUserUpdatedAction), bjensen},
		{string(models.SCIMUserUpdatedAction), bjensen},
	}, events)
}

func (ts *SCIMTestSuite) TestGroupsPatchReplay() {
	bjensen := ts.create(ts.TokenA, userWith("bjensen@example.com", "bjensen"))
	jsmith := ts.create(ts.TokenA, userWith("jsmith@example.com", "701984"))
	babs := ts.create(ts.TokenA, userWith("babs@jensen.org", "babs"))

	type state struct {
		displayName string
		members     []string
	}
	expected := map[string]state{
		"push group":    {"Tour Guides", []string{bjensen, jsmith}},
		"remove jsmith": {"Tour Guides", []string{bjensen}},
		"add babs":      {"Tour Guides", []string{bjensen, babs}},
		"rename":        {"Group B", []string{bjensen, babs}},
	}
	played := ts.replay("okta_group_patch.json", rfcGroup, []string{rfcBjensen, bjensen, rfcJsmith, jsmith, rfcBabs, babs}, nil, func(step, group string) {
		want, ok := expected[step]
		require.True(ts.T(), ok, step)
		ts.requireGroup(step, group, want.displayName, want.members)
	})
	require.Equal(ts.T(), len(expected), played)
}

func (ts *SCIMTestSuite) requireGroup(step, group, displayName string, members []string) {
	got := ts.get(ts.TokenA, "/Groups/"+group)
	require.Equal(ts.T(), displayName, got["displayName"], step)
	require.ElementsMatch(ts.T(), members, memberValues(got), step)
}

func (ts *SCIMTestSuite) TestWriteResponseMembersMatchGet() {
	ids := []string{}
	for _, name := range []string{"a", "b", "c", "d"} {
		ids = append(ids, ts.create(ts.TokenA, scimUser(name)))
	}
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", ids[2], ids[0]))
	requireMatchesGet := func(method, body string) {
		w, written := ts.do(ts.TokenA, method, "/Groups/"+id, body)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
		require.Equal(ts.T(), ts.get(ts.TokenA, "/Groups/"+id)["members"], written["members"])
	}
	requireMatchesGet(http.MethodPatch, patchOp(addMembers(ids[3], ids[1]), `{"op":"replace","path":"displayName","value":"Platform"}`))
	requireMatchesGet(http.MethodPatch, patchOp(removeMember(ids[2]), `{"op":"replace","path":"displayName","value":"Engineering"}`))
	requireMatchesGet(http.MethodPut, groupWith("Engineering", "", ids[1], ids[2], ids[3]))
	requireMatchesGet(http.MethodPatch, patchOp(`{"op":"replace","path":"displayName","value":"Platform"}`))
}

func (ts *SCIMTestSuite) TestPatchMembersDeltaMatchesFullPatch() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	carol := ts.create(ts.TokenA, userWith("carol@example.com", "c-1"))
	deleted := ts.create(ts.TokenA, userWith("dave@example.com", "d-1"))
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+deleted, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	other := ts.create(ts.TokenB, userWith("erin@example.com", "e-1"))

	type outcome struct {
		code      int
		scimType  any
		members   []string
		events    []string
		versioned bool
	}
	apply := func(query string, ops []string) outcome {
		id := ts.createGroup(ts.TokenA, groupWith("Engineering", "", alice, bob))
		before := ts.etag("/Groups/" + id)
		var result outcome
		result.events = actionsOf(ts.auditDuring(func() {
			w, got := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id+query, patchOp(ops...))
			result.code, result.scimType = w.Code, got["scimType"]
		}))
		result.members = memberValues(ts.get(ts.TokenA, "/Groups/"+id))
		result.versioned = ts.etag("/Groups/"+id) != before
		return result
	}

	for name, ops := range map[string][]string{
		"add new":            {addMembers(carol)},
		"add present":        {addMembers(alice)},
		"add duplicate":      {addMembers(carol, carol)},
		"remove present":     {removeMember(alice)},
		"remove absent":      {removeMember(carol)},
		"add and remove":     {addMembers(carol), removeMember(bob)},
		"uppercase":          {addMembers(strings.ToUpper(carol)), removeMember(strings.ToUpper(alice))},
		"remove non uuid":    {removeMember("nope")},
		"add non uuid":       {addMembers("nope")},
		"add deleted user":   {addMembers(deleted)},
		"add other provider": {addMembers(other)},
	} {
		delta, full := apply("", ops), apply("?attributes=members", ops)
		if full.code == http.StatusOK {
			require.Equal(ts.T(), http.StatusNoContent, delta.code, name)
			delta.code = full.code
		}
		require.Equal(ts.T(), full.code, delta.code, name)
		require.Equal(ts.T(), full.scimType, delta.scimType, name)
		require.Equal(ts.T(), full.members, delta.members, name)
		require.ElementsMatch(ts.T(), full.events, delta.events, name)
		require.Equal(ts.T(), full.versioned, delta.versioned, name)
	}
}

func (ts *SCIMTestSuite) TestPatchMembersDeltaChecksIfMatch() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", ""))
	current := ts.etag("/Groups/" + id)
	body := patchOp(addMembers(alice))

	w, _ := ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Groups/"+id, body, "If-Match", current)
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	next := w.Header().Get("ETag")
	require.NotEqual(ts.T(), current, next)
	require.Equal(ts.T(), next, ts.etag("/Groups/"+id))

	w, _ = ts.doAs(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Groups/"+id, body, "If-Match", current)
	require.Equal(ts.T(), http.StatusPreconditionFailed, w.Code, w.Body.String())

	w, _ = ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+uuid.Must(uuid.NewV4()).String(), body)
	require.Equal(ts.T(), http.StatusNotFound, w.Code, w.Body.String())
	w, _ = ts.do(ts.TokenB, http.MethodPatch, "/Groups/"+id, body)
	require.Equal(ts.T(), http.StatusNotFound, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) patchMembers(id string, ops ...string) map[string]any {
	w, _ := ts.do(ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(ops...))
	require.Equal(ts.T(), http.StatusNoContent, w.Code, w.Body.String())
	require.Empty(ts.T(), w.Body.String())
	return ts.get(ts.TokenA, "/Groups/"+id)
}

func (ts *SCIMTestSuite) TestConcurrentMemberAddsWithoutIfMatchLoseNoUpdates() {
	const existing, attempts = 10_000, 8
	seed := func(prefix string, n int) []uuid.UUID {
		rows := []struct {
			ID uuid.UUID `db:"id"`
		}{}
		require.NoError(ts.T(), ts.API.db.RawQuery(
			`INSERT INTO scim_users (id, sso_provider_id, resource) SELECT gen_random_uuid(), ?, jsonb_build_object('schemas', jsonb_build_array('urn:ietf:params:scim:schemas:core:2.0:User'), 'userName', ? || i || '@example.com', 'active', true) FROM generate_series(1, ?) i RETURNING id`,
			ts.A.ID, prefix, n,
		).All(&rows))
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.ID
		}
		return ids
	}
	id := ts.createGroup(ts.TokenA, groupWith("Engineering", "eng"))
	require.NoError(ts.T(), ts.API.db.RawQuery(
		`INSERT INTO scim_group_members (group_id, scim_user_id) SELECT ?, unnest(?::uuid[])`,
		id, seed("member", existing),
	).Exec())
	added := seed("joiner", attempts)
	require.NoError(ts.T(), ts.API.db.RawQuery(`ANALYZE scim_users, scim_group_members`).Exec())

	codes := make(chan int, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, member := range added {
		wg.Go(func() {
			<-start
			codes <- ts.serve(protocol.MediaType, ts.TokenA, http.MethodPatch, "/Groups/"+id, patchOp(addMembers(member.String()))).Code
		})
	}
	close(start)
	wg.Wait()
	close(codes)

	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	require.Equal(ts.T(), map[int]int{http.StatusNoContent: attempts}, counts)
	require.Len(ts.T(), memberValues(ts.get(ts.TokenA, "/Groups/"+id)), existing+attempts)
}

func (ts *SCIMTestSuite) TestConcurrentGroupWrites() {
	alice := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	bob := ts.create(ts.TokenA, userWith("bob@example.com", "b-1"))
	carol := ts.create(ts.TokenA, userWith("carol@example.com", "c-1"))
	addCarol := patchOp(addMembers(carol))
	addBob := func(tx *storage.Connection) error {
		return tx.RawQuery(`WITH added AS (INSERT INTO scim_group_members (group_id, scim_user_id) SELECT id, ? FROM scim_groups WHERE external_id = 'g-1') UPDATE scim_groups SET updated_at = clock_timestamp() WHERE external_id = 'g-1'`, bob).Exec()
	}
	rename := func(tx *storage.Connection) error {
		return tx.RawQuery(`UPDATE scim_groups SET resource = jsonb_set(resource, '{displayName}', '"Platform"'), updated_at = clock_timestamp() WHERE external_id = 'g-1'`).Exec()
	}

	for _, tc := range []struct {
		name, method, body string
		ifMatch            string
		finish             func(tx *storage.Connection) error
		code               int
		displayName        string
		members            []string
	}{
		{name: "patch merges a concurrent member add", method: http.MethodPatch, body: addCarol, finish: addBob, code: http.StatusNoContent, displayName: "Engineering", members: []string{alice, bob, carol}},
		{name: "patch with If-Match * merges a concurrent member add", method: http.MethodPatch, body: addCarol, ifMatch: "*", finish: addBob, code: http.StatusNoContent, displayName: "Engineering", members: []string{alice, bob, carol}},
		{name: "patch with If-Match rejects a concurrent member add", method: http.MethodPatch, body: addCarol, ifMatch: "etag", finish: addBob, code: http.StatusPreconditionFailed, displayName: "Engineering", members: []string{alice, bob}},
		{name: "patch rejects a concurrent rename", method: http.MethodPatch, body: addCarol, finish: rename, code: http.StatusConflict, displayName: "Platform", members: []string{alice}},
		{name: "put rejects a concurrent member add", method: http.MethodPut, body: groupWith("Engineering", "g-1", alice, carol), finish: addBob, code: http.StatusConflict, displayName: "Engineering", members: []string{alice, bob}},
	} {
		id := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
		var headers []string
		if tc.ifMatch != "" {
			headers = []string{"If-Match", tc.ifMatch}
		}
		if tc.ifMatch == "etag" {
			headers[1] = ts.etag("/Groups/" + id)
		}
		code, err := ts.whileLocked(
			func(tx *storage.Connection) error {
				return tx.RawQuery("SELECT 1 FROM scim_groups WHERE id = ? FOR UPDATE", id).Exec()
			},
			tc.finish,
			tc.method, "/Groups/"+id, tc.body, headers...,
		)
		require.NoError(ts.T(), err, tc.name)
		require.Equal(ts.T(), tc.code, code, tc.name)

		got := ts.get(ts.TokenA, "/Groups/"+id)
		require.Equal(ts.T(), tc.displayName, got["displayName"], tc.name)
		require.ElementsMatch(ts.T(), tc.members, memberValues(got), tc.name)
		w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Groups/"+id, "")
		require.Equal(ts.T(), http.StatusNoContent, w.Code, tc.name)
	}
}
