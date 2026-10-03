package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type scimBench struct {
	api      *API
	provider uuid.UUID
	token    string
}

func BenchmarkSCIMGroup(b *testing.B) {
	api := setupSCIMBenchAPI(b)
	for _, size := range []int{100, 1_000, 10_000} {
		bench := newSCIMBench(b, api)
		members := bench.seedUsers(b, "member", size)
		extra := bench.seedUsers(b, "extra", 1)[0]
		group := bench.seedGroup(b, members)
		require.NoError(b, api.db.RawQuery("ANALYZE").Exec())
		name := "members=" + strconv.Itoa(size)

		b.Run(name+"/get", func(b *testing.B) {
			bench.expectEach(b, http.StatusOK, http.MethodGet, "/Groups/"+group, "")
		})
		b.Run(name+"/get-excluding-members", func(b *testing.B) {
			bench.expectEach(b, http.StatusOK, http.MethodGet, "/Groups/"+group+"?excludedAttributes=members", "")
		})
		b.Run(name+"/patch-add-then-remove-one", func(b *testing.B) {
			add := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + extra.String() + `"}]}]}`
			remove := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"` + extra.String() + `\"]"}]}`
			bench.expectEach(b, http.StatusNoContent, http.MethodPatch, "/Groups/"+group, add, remove)
		})
		b.Run(name+"/patch-pathless-replace-unchanged", func(b *testing.B) {
			body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"id":"` + group + `","displayName":"Engineering"}}]}`
			bench.expectEach(b, http.StatusOK, http.MethodPatch, "/Groups/"+group, body)
		})
		b.Run(name+"/put-unchanged", func(b *testing.B) {
			body := putBody(group, members)
			b.ReportMetric(float64(len(body)), "req-bytes")
			bench.expectEach(b, http.StatusOK, http.MethodPut, "/Groups/"+group, body)
		})
		b.Run(name+"/put-add-then-remove-one", func(b *testing.B) {
			bodies := []string{putBody(group, append(slices.Clone(members), extra)), putBody(group, members)}
			b.ReportMetric(float64(len(bodies[0])), "req-bytes")
			bench.expectEach(b, http.StatusOK, http.MethodPut, "/Groups/"+group, bodies...)
		})
		b.Run(name+"/delete", func(b *testing.B) {
			for range b.N {
				b.StopTimer()
				doomed := bench.seedGroup(b, members)
				b.StartTimer()
				bench.expect(b, http.StatusNoContent, http.MethodDelete, "/Groups/"+doomed, "")
			}
		})
	}
}

func BenchmarkSCIMUser(b *testing.B) {
	bench := newSCIMBench(b, setupSCIMBenchAPI(b))
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(b, json.Unmarshal(bench.expect(b, http.StatusCreated, http.MethodPost, "/Users", userBody("", "one")).Body.Bytes(), &created))
	id := created.ID

	b.Run("put-title", func(b *testing.B) {
		bench.expectEach(b, http.StatusOK, http.MethodPut, "/Users/"+id, userBody(id, "one"), userBody(id, "two"))
	})
	b.Run("patch-title", func(b *testing.B) {
		bench.expectEach(b, http.StatusOK, http.MethodPatch, "/Users/"+id, patchTitle("one"), patchTitle("two"))
	})
	b.Run("patch-active-unchanged", func(b *testing.B) {
		bench.expectEach(b, http.StatusOK, http.MethodPatch, "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`)
	})
}

func setupSCIMBenchAPI(b *testing.B) *API {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, _ *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			config.RateLimitScim = 1_000_000_000
		}
	})
	require.NoError(b, err)
	output, formatter := logrus.StandardLogger().Out, logrus.StandardLogger().Formatter
	logrus.SetOutput(io.Discard)
	logrus.SetFormatter(observability.NewCustomFormatter())
	b.Cleanup(func() {
		logrus.SetOutput(output)
		logrus.SetFormatter(formatter)
		require.NoError(b, api.db.Close())
	})
	return api
}

func newSCIMBench(b *testing.B, api *API) *scimBench {
	require.NoError(b, models.TruncateAll(api.db))
	provider, token := createSSOProviderWithSCIMToken(b, api.db)
	return &scimBench{api: api, provider: provider.ID, token: token}
}

func putBody(group string, members []uuid.UUID) string {
	entries := make([]string, len(members))
	for i, id := range members {
		entries[i] = `{"value":"` + id.String() + `","display":"member` + strconv.Itoa(i) + `@example.com"}`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"` + group + `","displayName":"Engineering","members":[` + strings.Join(entries, ",") + `]}`
}

func userBody(id, title string) string {
	var idField string
	if id != "" {
		idField = `"id":"` + id + `",`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],` + idField + `"userName":"bjensen@example.com","title":"` + title + `","active":true,"emails":[{"value":"bjensen@example.com","primary":true}]}`
}

func patchTitle(title string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"` + title + `"}]}`
}

func (s *scimBench) seedUsers(b *testing.B, prefix string, n int) []uuid.UUID {
	rows := []struct {
		ID uuid.UUID `db:"id"`
	}{}
	require.NoError(b, s.api.db.RawQuery(
		`INSERT INTO scim_users (id, sso_provider_id, resource) SELECT gen_random_uuid(), ?, jsonb_build_object('schemas', jsonb_build_array('urn:ietf:params:scim:schemas:core:2.0:User'), 'userName', ? || i || '@example.com', 'active', true) FROM generate_series(1, ?) i RETURNING id`,
		s.provider, prefix, n,
	).All(&rows))
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func (s *scimBench) seedGroup(b *testing.B, members []uuid.UUID) string {
	var row struct {
		ID uuid.UUID `db:"id"`
	}
	require.NoError(b, s.api.db.RawQuery(
		`INSERT INTO scim_groups (id, sso_provider_id, resource) VALUES (gen_random_uuid(), ?, '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering"}'::jsonb) RETURNING id`,
		s.provider,
	).First(&row))
	require.NoError(b, s.api.db.RawQuery(
		`INSERT INTO scim_group_members (group_id, scim_user_id) SELECT ?, unnest(?::uuid[])`,
		row.ID, members,
	).Exec())
	return row.ID.String()
}

func (s *scimBench) expectEach(b *testing.B, status int, method, path string, bodies ...string) {
	i := 0
	for b.Loop() {
		s.expect(b, status, method, path, bodies[i%len(bodies)])
		i++
	}
}

func (s *scimBench) expect(b *testing.B, status int, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Content-Type", protocol.MediaType)
	w := httptest.NewRecorder()
	s.api.handler.ServeHTTP(w, r)
	if w.Code != status {
		b.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, status, w.Body.String())
	}
	b.ReportMetric(float64(w.Body.Len()), "resp-bytes")
	return w
}
