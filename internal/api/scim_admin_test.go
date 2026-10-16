package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/scimtest"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/models"
)

func TestSCIMAdminTokens(t *testing.T) {
	c := newSCIMClient(t, nil)
	scimPath := c.adminPath()
	tokensPath := scimPath + "/tokens"
	status := func(t *testing.T, method string) api.AdminSCIMStatusResponse {
		res := c.admin(t, method, scimPath, nil)
		require.Equal(t, http.StatusOK, res.StatusCode)
		return scimtest.Decode[api.AdminSCIMStatusResponse](t, res)
	}
	create := func(t *testing.T, body any) api.AdminSCIMTokenCreateResponse {
		res := c.admin(t, http.MethodPost, tokensPath, body)
		require.Equal(t, http.StatusCreated, res.StatusCode)
		return scimtest.Decode[api.AdminSCIMTokenCreateResponse](t, res)
	}
	revoke := func(t *testing.T, id string) *http.Response {
		return c.admin(t, http.MethodDelete, tokensPath+"/"+id, nil)
	}

	t.Run("GET shows status and active tokens", func(t *testing.T) {
		got := status(t, http.MethodGet)
		require.True(t, got.Enabled)
		require.NotEmpty(t, got.BaseURL)
		require.NotEmpty(t, got.Tokens)
		for _, token := range got.Tokens {
			require.Nil(t, token.RevokedAt)
		}
	})

	t.Run("DELETE and POST toggle SCIM and repeat safely", func(t *testing.T) {
		for _, step := range []struct {
			method  string
			enabled bool
		}{{http.MethodDelete, false}, {http.MethodDelete, false}, {http.MethodPost, true}, {http.MethodPost, true}} {
			require.Equal(t, step.enabled, status(t, step.method).Enabled, step.method)
		}
	})

	t.Run("POST tokens creates a token that authenticates", func(t *testing.T) {
		token := create(t, nil)
		require.True(t, strings.HasPrefix(token.Token, "scim_"))
		require.Equal(t, token.Token[:len(token.Prefix)], token.Prefix)
		require.NotEmpty(t, token.BaseURL)
		require.Nil(t, token.ExpiresAt)
		require.Equal(t, http.StatusOK, c.as(token.Token).api.Get(t, scimUsersPath).StatusCode)
	})

	t.Run("POST tokens with expires_at", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		token := create(t, map[string]any{"expires_at": expiresAt})
		require.NotNil(t, token.ExpiresAt)
		require.True(t, expiresAt.Equal(*token.ExpiresAt))

		res := c.admin(t, http.MethodPost, tokensPath, map[string]any{"expires_at": time.Now().Add(-time.Hour)})
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("DELETE token revokes once and repeats safely", func(t *testing.T) {
		token := create(t, nil)
		first := revoke(t, token.ID.String())
		require.Equal(t, http.StatusOK, first.StatusCode)
		revoked := scimtest.Decode[models.SCIMToken](t, first)
		require.NotNil(t, revoked.RevokedAt)

		second := revoke(t, token.ID.String())
		require.Equal(t, http.StatusOK, second.StatusCode)
		require.Equal(t, revoked, scimtest.Decode[models.SCIMToken](t, second))

		require.Equal(t, http.StatusUnauthorized, c.as(token.Token).api.Get(t, scimUsersPath).StatusCode)
		require.NotContains(t, status(t, http.MethodGet).Tokens, revoked)

		res := c.admin(t, http.MethodGet, tokensPath, nil)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Contains(t, scimtest.Decode[api.AdminSCIMTokenListResponse](t, res).Tokens, revoked)
	})

	t.Run("DELETE token returns 404 for a token it cannot find", func(t *testing.T) {
		other := newSCIMClient(t, nil)
		foreign, _, err := models.CreateSCIMToken(other.inst.Conn, uuid.UUID(other.provider.ID), nil)
		require.NoError(t, err)

		want := string(scimBody(t, revoke(t, "not-a-uuid")))
		require.Contains(t, want, `"error_code":"sso_provider_not_found"`)
		for _, id := range []string{uuid.NewV7().String(), foreign.ID.String()} {
			res := revoke(t, id)
			require.Equal(t, http.StatusNotFound, res.StatusCode, id)
			require.Equal(t, want, string(scimBody(t, res)), id)
		}
	})
}
