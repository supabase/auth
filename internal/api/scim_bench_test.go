package api

import (
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

type scimGroupBench struct {
	api      *API
	provider uuid.UUID
	token    string
}

func BenchmarkSCIMGroup(b *testing.B) {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, _ *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			config.RateLimitScim = 1_000_000_000
		}
	})
	require.NoError(b, err)
	defer func() { require.NoError(b, api.db.Close()) }()
	output, formatter := logrus.StandardLogger().Out, logrus.StandardLogger().Formatter
	logrus.SetOutput(io.Discard)
	logrus.SetFormatter(observability.NewCustomFormatter())
	defer func() {
		logrus.SetOutput(output)
		logrus.SetFormatter(formatter)
	}()

	for _, size := range []int{100, 1_000, 10_000} {
		require.NoError(b, models.TruncateAll(api.db))
		provider, token := createSSOProviderWithSCIMToken(b, api.db)
		bench := &scimGroupBench{api: api, provider: provider.ID, token: token}
		members := bench.seedUsers(b, "member", size)
		extra := bench.seedUsers(b, "extra", 1)[0]
		group := bench.seedGroup(b, members)
		require.NoError(b, api.db.RawQuery("ANALYZE").Exec())
		name := "members=" + strconv.Itoa(size)

		b.Run(name+"/get", func(b *testing.B) {
			for b.Loop() {
				bench.expect(b, http.StatusOK, http.MethodGet, "/Groups/"+group, "")
			}
		})
		b.Run(name+"/get-excluding-members", func(b *testing.B) {
			for b.Loop() {
				bench.expect(b, http.StatusOK, http.MethodGet, "/Groups/"+group+"?excludedAttributes=members", "")
			}
		})
		b.Run(name+"/patch-add-then-remove-one", func(b *testing.B) {
			add := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + extra.String() + `"}]}]}`
			remove := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"` + extra.String() + `\"]"}]}`
			i := 0
			for b.Loop() {
				body := add
				if i%2 == 1 {
					body = remove
				}
				bench.expect(b, http.StatusNoContent, http.MethodPatch, "/Groups/"+group, body)
				i++
			}
		})
		b.Run(name+"/patch-pathless-replace-unchanged", func(b *testing.B) {
			body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"id":"` + group + `","displayName":"Engineering"}}]}`
			for b.Loop() {
				bench.expect(b, http.StatusOK, http.MethodPatch, "/Groups/"+group, body)
			}
		})
		b.Run(name+"/put-unchanged", func(b *testing.B) {
			body := putBody(group, members)
			b.ReportMetric(float64(len(body)), "req-bytes")
			for b.Loop() {
				bench.expect(b, http.StatusOK, http.MethodPut, "/Groups/"+group, body)
			}
		})
		b.Run(name+"/put-add-then-remove-one", func(b *testing.B) {
			bodies := []string{putBody(group, append(slices.Clone(members), extra)), putBody(group, members)}
			b.ReportMetric(float64(len(bodies[0])), "req-bytes")
			i := 0
			for b.Loop() {
				bench.expect(b, http.StatusOK, http.MethodPut, "/Groups/"+group, bodies[i%2])
				i++
			}
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

func putBody(group string, members []uuid.UUID) string {
	entries := make([]string, len(members))
	for i, id := range members {
		entries[i] = `{"value":"` + id.String() + `","display":"member` + strconv.Itoa(i) + `@example.com"}`
	}
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"` + group + `","displayName":"Engineering","members":[` + strings.Join(entries, ",") + `]}`
}

func (s *scimGroupBench) seedUsers(b *testing.B, prefix string, n int) []uuid.UUID {
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

func (s *scimGroupBench) seedGroup(b *testing.B, members []uuid.UUID) string {
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

func (s *scimGroupBench) expect(b *testing.B, status int, method, path, body string) {
	r := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Content-Type", protocol.MediaType)
	w := httptest.NewRecorder()
	s.api.handler.ServeHTTP(w, r)
	if w.Code != status {
		b.Fatalf("%s %s: got %d, want %d: %s", method, path, w.Code, status, w.Body.String())
	}
	b.ReportMetric(float64(w.Body.Len()), "resp-bytes")
}
