package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
)

func (ts *SCIMTestSuite) TestTenantIsolation() {
	idA := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	idB := ts.create(ts.TokenB, userWith("bob@example.com", "b-1"))

	listA := ts.list(ts.TokenA, "")
	require.EqualValues(ts.T(), 1, listA["totalResults"])
	require.Equal(ts.T(), idA, listA["Resources"].([]any)[0].(map[string]any)["id"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "bob@example.com"`)["totalResults"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `externalId eq "b-1"`)["totalResults"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "bob@example.com" and externalId eq "b-1"`)["totalResults"])

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, userWith("bob@example.com", "b-1")},
		{http.MethodPatch, patchOp(`{"op":"replace","value":{"active":false}}`)},
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

func (ts *SCIMTestSuite) TestTenantIsolationWithSameEmail() {
	body := userWith("shared@example.com", "shared-1")
	ids := map[string]string{ts.TokenA: ts.create(ts.TokenA, body), ts.TokenB: ts.create(ts.TokenB, body)}
	require.NotEqual(ts.T(), ids[ts.TokenA], ids[ts.TokenB])
	require.NotEqual(ts.T(), ts.linkedUser(ids[ts.TokenA]).ID, ts.linkedUser(ids[ts.TokenB]).ID)

	for token, other := range map[string]string{ts.TokenA: ts.TokenB, ts.TokenB: ts.TokenA} {
		for _, filter := range []string{"", `userName eq "shared@example.com"`, `externalId eq "shared-1"`} {
			found := ts.list(token, filter)
			require.EqualValues(ts.T(), 1, found["totalResults"], filter)
			require.Equal(ts.T(), ids[token], found["Resources"].([]any)[0].(map[string]any)["id"], filter)
		}
		w, _ := ts.do(token, http.MethodGet, "/Users/"+ids[other], "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code)
	}

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+ids[ts.TokenA], "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w, got := ts.do(ts.TokenB, http.MethodGet, "/Users/"+ids[ts.TokenB], "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), true, got["active"])
}

func (ts *SCIMTestSuite) TestTombstonedUsersInvisibleToBothProviders() {
	id := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	group := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", id))
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	for _, token := range []string{ts.TokenA, ts.TokenB} {
		w, _ := ts.do(token, http.MethodGet, "/Users/"+id, "")
		require.Equal(ts.T(), http.StatusNotFound, w.Code)
		for _, filter := range []string{"", `userName eq "alice@example.com"`, `externalId eq "a-1"`} {
			require.EqualValues(ts.T(), 0, ts.list(token, filter)["totalResults"], filter)
		}
	}

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+group, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Empty(ts.T(), memberValues(got))
}

func (ts *SCIMTestSuite) TestRevokedAndExpiredTokensRefusedEverywhere() {
	user := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	group := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", user))

	tokens, err := models.FindSCIMTokensBySSOProvider(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), tokens, 1)
	require.NoError(ts.T(), tokens[0].Revoke(ts.API.db))

	expiresAt := time.Now().Add(time.Hour)
	expired, expiredToken, err := models.CreateSCIMToken(ts.API.db, ts.A, &expiresAt)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"UPDATE "+expired.TableName()+" SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = ?", expired.ID,
	).Exec())

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/ResourceTypes", ""},
		{http.MethodGet, "/ResourceTypes/User", ""},
		{http.MethodGet, "/ResourceTypes/Group", ""},
		{http.MethodGet, "/Schemas", ""},
		{http.MethodGet, "/Schemas/" + string(core.SchemaUser), ""},
		{http.MethodGet, "/Schemas/" + string(core.SchemaGroup), ""},
		{http.MethodGet, "/Users", ""},
		{http.MethodPost, "/Users", userWith("bob@example.com", "b-1")},
		{http.MethodGet, "/Users/" + user, ""},
		{http.MethodPut, "/Users/" + user, userWith("alice@example.com", "a-2")},
		{http.MethodPatch, "/Users/" + user, patchOp(`{"op":"replace","value":{"active":false}}`)},
		{http.MethodDelete, "/Users/" + user, ""},
		{http.MethodGet, "/Groups", ""},
		{http.MethodPost, "/Groups", groupWith("Platform", "g-2")},
		{http.MethodGet, "/Groups/" + group, ""},
		{http.MethodPut, "/Groups/" + group, groupWith("Owned", "g-1")},
		{http.MethodPatch, "/Groups/" + group, patchOp(`{"op":"replace","path":"displayName","value":"Owned"}`)},
		{http.MethodDelete, "/Groups/" + group, ""},
	}
	for name, token := range map[string]string{"revoked": ts.TokenA, "expired": expiredToken} {
		w, _ := ts.do(token, http.MethodGet, "/ServiceProviderConfig", "")
		require.Equal(ts.T(), http.StatusOK, w.Code, name+" GET /ServiceProviderConfig")
		for _, route := range routes {
			w, _ := ts.do(token, route.method, route.path, route.body)
			require.Equal(ts.T(), http.StatusUnauthorized, w.Code, name+" "+route.method+" "+route.path)
			require.True(ts.T(), strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer"), name+" "+route.method+" "+route.path)
		}
	}

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", user).First(&row))
	require.True(ts.T(), row.Active)
	require.Nil(ts.T(), row.DeletedAt)
	require.Contains(ts.T(), string(row.Resource), `"a-1"`)
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))

	var stored models.SCIMGroup
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", group).First(&stored))
	require.Contains(ts.T(), string(stored.Resource), "Engineering")
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMGroup{}, "sso_provider_id = ?", ts.A.ID))
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMGroupMember{}, "group_id = ?", group))

	w, _ := ts.do(ts.TokenB, http.MethodGet, "/Users", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMTestSuite) TestGroupsTenantIsolation() {
	aliceA := ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))
	groupA := ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", aliceA))

	require.EqualValues(ts.T(), 0, ts.listGroups(ts.TokenB, "")["totalResults"])
	require.EqualValues(ts.T(), 0, ts.listGroups(ts.TokenB, `displayName eq "Engineering"`)["totalResults"])

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, groupWith("Engineering", "g-1")},
		{http.MethodPatch, patchOp(`{"op":"replace","path":"displayName","value":"Owned"}`)},
		{http.MethodDelete, ""},
	} {
		w, _ := ts.do(ts.TokenB, tc.method, "/Groups/"+groupA, tc.body)
		require.Equal(ts.T(), http.StatusNotFound, w.Code, tc.method)
	}

	w, got := ts.do(ts.TokenA, http.MethodGet, "/Groups/"+groupA, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), "Engineering", got["displayName"])
	require.Equal(ts.T(), []string{aliceA}, memberValues(got))

	bobB := ts.create(ts.TokenB, userWith("bob@example.com", "b-1"))
	groupB := ts.createGroup(ts.TokenB, groupWith("Engineering", "g-1", bobB))
	for _, filter := range []string{"", `displayName eq "Engineering"`, `externalId eq "g-1"`} {
		found := ts.listGroups(ts.TokenB, filter)
		require.EqualValues(ts.T(), 1, found["totalResults"], filter)
		require.Equal(ts.T(), groupB, found["Resources"].([]any)[0].(map[string]any)["id"], filter)
	}

	for _, tc := range []struct{ method, body string }{
		{http.MethodPut, groupWith("Engineering", "g-1", aliceA, bobB)},
		{http.MethodPatch, patchOp(`{"op":"add","path":"members","value":[{"value":"` + bobB + `"}]}`)},
	} {
		w, body := ts.do(ts.TokenA, tc.method, "/Groups/"+groupA, tc.body)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code, tc.method+" "+w.Body.String())
		require.Equal(ts.T(), "invalidValue", body["scimType"], tc.method)
	}

	w, _ = ts.do(ts.TokenB, http.MethodDelete, "/Users/"+bobB, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	w, got = ts.do(ts.TokenA, http.MethodGet, "/Groups/"+groupA, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), []string{aliceA}, memberValues(got))
	w, user := ts.do(ts.TokenA, http.MethodGet, "/Users/"+aliceA, "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Len(ts.T(), user["groups"], 1)
	require.Equal(ts.T(), groupA, user["groups"].([]any)[0].(map[string]any)["value"])
}
