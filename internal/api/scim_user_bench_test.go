package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func BenchmarkSCIMUser(b *testing.B) {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, _ *storage.Connection) {
		if config != nil {
			config.SSO.SCIM.Enabled = true
			config.RateLimitScim = 1_000_000_000
		}
	})
	require.NoError(b, err)
	defer func() { require.NoError(b, api.db.Close()) }()
	output := logrus.StandardLogger().Out
	logrus.SetOutput(io.Discard)
	defer logrus.SetOutput(output)

	require.NoError(b, models.TruncateAll(api.db))
	provider, token := createSSOProviderWithSCIMToken(b, api.db)
	bench := &scimGroupBench{api: api, provider: provider.ID, token: token}
	r := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(userBody("", "one")))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", protocol.MediaType)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, r)
	require.Equal(b, http.StatusCreated, w.Code, w.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(b, json.Unmarshal(w.Body.Bytes(), &created))
	id := created.ID

	b.Run("put-title", func(b *testing.B) {
		bodies := []string{userBody(id, "one"), userBody(id, "two")}
		i := 0
		for b.Loop() {
			bench.expect(b, http.StatusOK, http.MethodPut, "/Users/"+id, bodies[i%2])
			i++
		}
	})
	b.Run("patch-title", func(b *testing.B) {
		bodies := []string{patchTitle("one"), patchTitle("two")}
		i := 0
		for b.Loop() {
			bench.expect(b, http.StatusOK, http.MethodPatch, "/Users/"+id, bodies[i%2])
			i++
		}
	})
	b.Run("patch-active-unchanged", func(b *testing.B) {
		body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`
		for b.Loop() {
			bench.expect(b, http.StatusOK, http.MethodPatch, "/Users/"+id, body)
		}
	})
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
