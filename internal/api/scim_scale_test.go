package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/pop/v6/logging"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
)

const scimScaleUsers = 100_000

type scimScale struct {
	scimClient
	big, small, user string
	spare            []string
}

func TestSCIMScale(t *testing.T) {
	if os.Getenv("SCIM_SCALE") == "" {
		t.Skip("set SCIM_SCALE=1 to seed 300K resources and time the SCIM endpoints")
	}
	s := seedSCIMScale(t)
	report := []string{}
	timed := func(name, method, path string, body any, want ...int) {
		var res *http.Response
		var raw []byte
		median, slowest := scimMedian(3, func() {
			res = s.do(t, method, path, body)
			raw = scimBody(t, res)
		})
		require.Contains(t, want, res.StatusCode, "%s: %s", name, string(raw))
		report = append(report, fmt.Sprintf("| %s | %d | %s | %s | %d |", name, res.StatusCode, median.Round(time.Millisecond), slowest.Round(time.Millisecond), len(raw)))
	}
	member := func(op, value string) map[string]any {
		if op == "remove" {
			return newSCIMPatch(map[string]any{"op": op, "path": `members[value eq "` + value + `"]`})
		}
		return newSCIMPatch(map[string]any{"op": op, "path": "members", "value": []core.Member{{Value: value}}})
	}
	rename := newSCIMPatch(map[string]any{"op": "replace", "value": map[string]any{"id": s.big, "displayName": "Everyone"}})

	timed("GET Users userName eq", http.MethodGet, scimUsersPath+"?"+url.Values{"filter": {`userName eq "user50000@example.com"`}}.Encode(), nil, http.StatusOK)
	timed("GET Users title co", http.MethodGet, scimUsersPath+"?"+url.Values{"filter": {`title co "ngineer"`}}.Encode(), nil, http.StatusOK)
	timed("GET Users emails.value eq", http.MethodGet, scimUsersPath+"?"+url.Values{"filter": {`emails.value eq "user50000@example.com"`}}.Encode(), nil, http.StatusOK)
	timed("GET Users active eq true", http.MethodGet, scimUsersPath+"?"+url.Values{"filter": {`active eq true`}}.Encode(), nil, http.StatusOK)
	timed("GET Users page 900", http.MethodGet, scimUsersPath+"?startIndex=90001&count=100", nil, http.StatusOK)
	timed("GET User in nested groups", http.MethodGet, scimUsersPath+"/"+s.user, nil, http.StatusOK)
	timed("GET Groups displayName eq, no members", http.MethodGet, scimGroupsPath+"?"+url.Values{"filter": {`displayName eq "big"`}, "excludedAttributes": {"members"}}.Encode(), nil, http.StatusOK)
	timed("GET Groups members.value eq", http.MethodGet, scimGroupsPath+"?"+url.Values{"filter": {`members.value eq "` + s.user + `"`}, "excludedAttributes": {"members"}}.Encode(), nil, http.StatusOK)
	timed("GET Groups list", http.MethodGet, scimGroupsPath, nil, http.StatusOK)
	timed("GET Group 10K", http.MethodGet, scimGroupsPath+"/"+s.small, nil, http.StatusOK)
	timed("GET Group 100K", http.MethodGet, scimGroupsPath+"/"+s.big, nil, http.StatusOK)
	timed("PATCH 100K add 1", http.MethodPatch, scimGroupsPath+"/"+s.big, member("add", s.spare[0]), http.StatusNoContent)
	timed("PATCH 100K remove 1", http.MethodPatch, scimGroupsPath+"/"+s.big, member("remove", s.spare[0]), http.StatusNoContent)
	timed("PATCH 100K replace displayName", http.MethodPatch, scimGroupsPath+"/"+s.big, rename, http.StatusOK)
	timed("PATCH 10K add 1", http.MethodPatch, scimGroupsPath+"/"+s.small, member("add", s.spare[0]), http.StatusNoContent)
	parent := seedSCIMGroup(t, s.scimClient, "parent")
	walk := scimCapture(t, "WITH RECURSIVE walk", func() {
		timed("PATCH nest 100K group", http.MethodPatch, scimGroupsPath+"/"+parent, member("add", s.big), http.StatusNoContent)
	})
	s.requireGroupHas(t, parent, s.big)
	t.Log(s.explain(t, walk))
	timed("PATCH nest 10K group", http.MethodPatch, scimGroupsPath+"/"+parent, member("add", s.small), http.StatusNoContent)

	var sizes struct {
		Table  string `db:"table_size"`
		Search string `db:"search_size"`
		GIN    string `db:"gin_size"`
	}
	require.NoError(t, s.inst.Conn.RawQuery(`SELECT pg_size_pretty(pg_total_relation_size('scim_resources')) AS table_size,
		(SELECT pg_size_pretty(sum(pg_column_size(search))) FROM scim_resources) AS search_size,
		pg_size_pretty(pg_relation_size('scim_resources_resource_idx')) AS gin_size`).First(&sizes))
	report = append(report, fmt.Sprintf("| sizes: table %s, search column %s, GIN %s | | | | |", sizes.Table, sizes.Search, sizes.GIN))

	statuses := s.concurrently(t, s.spare[1:])
	report = append(report, fmt.Sprintf("| PATCH 100K add, %d concurrent | %v | | | |", len(s.spare)-1, statuses))

	put := newSCIMGroup("Everyone")
	put["members"] = s.members(t, s.big)
	timed("PUT 100K", http.MethodPut, scimGroupsPath+"/"+s.big, put, http.StatusOK, http.StatusRequestEntityTooLarge)

	start := time.Now()
	res := s.delete(t, scimGroupsPath+"/"+s.big)
	require.Equal(t, http.StatusNoContent, res.StatusCode)
	report = append(report, fmt.Sprintf("| DELETE Group 100K | %d | %s | | |", res.StatusCode, time.Since(start).Round(time.Millisecond)))

	start = time.Now()
	require.NoError(t, s.inst.Conn.Destroy(s.provider))
	report = append(report, fmt.Sprintf("| DELETE sso provider cascade | | %s | | |", time.Since(start).Round(time.Millisecond)))

	t.Log("\n| Case | Status | Median | Max | Bytes |\n| --- | --- | --- | --- | --- |\n" + strings.Join(report, "\n"))
}

func seedSCIMScale(t *testing.T) scimScale {
	c := newSCIMClient(t, nil)
	for range 2 {
		noise := &models.SSOProvider{}
		require.NoError(t, c.inst.Conn.Create(noise))
		t.Cleanup(func() { require.NoError(t, c.inst.Conn.Destroy(noise)) })
		seedSCIMUsers(t, c, uuid.UUID(noise.ID))
	}
	seedSCIMUsers(t, c, uuid.UUID(c.provider.ID))
	s := scimScale{scimClient: c, big: seedSCIMGroup(t, c, "big"), small: seedSCIMGroup(t, c, "small")}
	require.NoError(t, c.inst.Conn.RawQuery(`INSERT INTO scim_resource_references (sso_provider_id, source_id, attribute, target_id, target_type)
		SELECT sso_provider_id, CASE WHEN n <= ? THEN ?::uuid ELSE ?::uuid END, 'members', id, 'User'
		FROM (SELECT sso_provider_id, id, row_number() OVER (ORDER BY id) n FROM scim_resources WHERE sso_provider_id = ? AND resource_type = 'User') u
		WHERE n <= ?`, 10_000, s.small, s.big, c.provider.ID, 10_000).Exec())
	require.NoError(t, c.inst.Conn.RawQuery(`INSERT INTO scim_resource_references (sso_provider_id, source_id, attribute, target_id, target_type)
		SELECT sso_provider_id, ?::uuid, 'members', id, 'User'
		FROM (SELECT sso_provider_id, id, row_number() OVER (ORDER BY id) n FROM scim_resources WHERE sso_provider_id = ? AND resource_type = 'User') u
		WHERE n <= ?`, s.big, c.provider.ID, scimScaleUsers-20).Exec())
	ids := []string{}
	require.NoError(t, c.inst.Conn.RawQuery(`SELECT id FROM scim_resources WHERE sso_provider_id = ? AND resource_type = 'User' ORDER BY id`, c.provider.ID).All(&ids))
	s.user, s.spare = ids[0], ids[len(ids)-11:]
	nested := []string{}
	for i := range 50 {
		group := seedSCIMGroup(t, c, fmt.Sprintf("nested%d", i))
		nested = append(nested, group)
		require.Equal(t, http.StatusNoContent, c.addMembers(t, group, s.user).StatusCode)
	}
	require.Equal(t, http.StatusNoContent, c.addMembers(t, s.small, nested...).StatusCode)
	require.NoError(t, c.inst.Conn.RawQuery("VACUUM ANALYZE scim_resources").Exec())
	require.NoError(t, c.inst.Conn.RawQuery("VACUUM ANALYZE scim_resource_references").Exec())
	return s
}

func seedSCIMUsers(t *testing.T, c scimClient, provider uuid.UUID) {
	require.NoError(t, c.inst.Conn.RawQuery(`INSERT INTO scim_resources (id, sso_provider_id, resource_type, resource)
		SELECT gen_random_uuid(), ?, 'User', jsonb_build_object(
			'userName', 'user' || n || '@example.com',
			'externalId', 'ext' || n,
			'active', n % 10 <> 0,
			'title', CASE WHEN n % 3 = 0 THEN 'Engineer' ELSE 'Manager' END,
			'name', jsonb_build_object('givenName', 'Given' || n, 'familyName', 'Family' || n),
			'emails', jsonb_build_array(jsonb_build_object('value', 'user' || n || '@example.com', 'type', 'work', 'primary', true)))
		FROM generate_series(1, ?) n`, provider, scimScaleUsers).Exec())
}

func seedSCIMGroup(t *testing.T, c scimClient, displayName string) string {
	return scimCreate[core.Group](t, c, scimGroupsPath, newSCIMGroup(displayName)).ID
}

func (s scimScale) members(t *testing.T, id string) []core.Member {
	members := []core.Member{}
	for _, member := range s.group(t, id).Members {
		members = append(members, core.Member{Value: member.Value})
	}
	return members
}

func (s scimScale) concurrently(t *testing.T, values []string) map[int]int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	statuses := map[int]int{}
	for _, value := range values {
		req := scimRequest(t, http.MethodPatch, scimGroupsPath+"/"+s.big, newSCIMPatch(map[string]any{"op": "add", "path": "members", "value": []core.Member{{Value: value}}}))
		wg.Go(func() {
			res, err := s.inst.DoAuth(req, s.token)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				statuses[0]++
				return
			}
			statuses[res.StatusCode]++
			_ = res.Body.Close()
		})
	}
	wg.Wait()
	return statuses
}

func scimMedian(runs int, run func()) (time.Duration, time.Duration) {
	durations := make([]time.Duration, runs)
	for i := range durations {
		start := time.Now()
		run()
		durations[i] = time.Since(start)
	}
	slices.Sort(durations)
	return durations[runs/2], durations[runs-1]
}

type scimQuery struct {
	sql  string
	args []any
}

func scimCapture(t *testing.T, marker string, run func()) scimQuery {
	var captured scimQuery
	pop.SetTxLogger(func(_ logging.Level, _ any, sql string, values ...any) {
		if strings.Contains(sql, marker) && captured.sql == "" {
			captured = scimQuery{sql, values}
		}
	})
	defer pop.SetTxLogger(func(logging.Level, any, string, ...any) {})
	run()
	require.NotEmpty(t, captured.sql, marker)
	return captured
}

func (s scimScale) explain(t *testing.T, q scimQuery) string {
	plans := []struct {
		Line string `db:"QUERY PLAN"`
	}{}
	require.NoError(t, s.inst.Conn.RawQuery("EXPLAIN (ANALYZE, BUFFERS) "+q.sql, q.args...).All(&plans))
	lines := []string{}
	for _, plan := range plans {
		lines = append(lines, plan.Line)
	}
	return strings.Join(lines, "\n")
}

func (s scimScale) requireGroupHas(t *testing.T, id, member string) {
	res := s.get(t, scimGroupsPath+"/"+id)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, string(scimBody(t, res)), member)
}
