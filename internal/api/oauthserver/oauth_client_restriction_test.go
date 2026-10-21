package oauthserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

func TestOAuthServer_OAuthClientTokenRejected(t *testing.T) {
	config := &conf.GlobalConfiguration{
		SiteURL: "https://example.com",
	}
	server := &Server{
		config: config,
	}

	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	user := &models.User{
		ID: userID,
	}
	oauthSession := &models.Session{
		ID:            uuid.Must(uuid.NewV4()),
		UserID:        userID,
		OAuthClientID: &clientID,
	}

	createOAuthContext := func(urlParamKey, urlParamVal string) (context.Context, *http.Request) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		ctx := req.Context()
		ctx = shared.WithUser(ctx, user)
		ctx = shared.WithSession(ctx, oauthSession)
		if urlParamKey != "" {
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add(urlParamKey, urlParamVal)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		}
		return ctx, req.WithContext(ctx)
	}

	t.Run("OAuthServerGetAuthorization rejects OAuth client session", func(t *testing.T) {
		ctx, req := createOAuthContext("authorization_id", "test-auth-id")
		w := httptest.NewRecorder()

		err := server.OAuthServerGetAuthorization(w, req.WithContext(ctx))
		require.Error(t, err)

		httpErr, ok := err.(*apierrors.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
		assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
	})

	t.Run("OAuthServerConsent rejects OAuth client session", func(t *testing.T) {
		body := bytes.NewBufferString(`{"action":"approve"}`)
		req := httptest.NewRequest(http.MethodPost, "/test", body)
		req.Header.Set("Origin", "https://example.com")
		ctx := req.Context()
		ctx = shared.WithUser(ctx, user)
		ctx = shared.WithSession(ctx, oauthSession)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("authorization_id", "test-auth-id")
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		err := server.OAuthServerConsent(w, req.WithContext(ctx))
		require.Error(t, err)

		httpErr, ok := err.(*apierrors.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
		assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
	})

	t.Run("UserListOAuthGrants rejects OAuth client session", func(t *testing.T) {
		ctx, req := createOAuthContext("", "")
		w := httptest.NewRecorder()

		err := server.UserListOAuthGrants(w, req.WithContext(ctx))
		require.Error(t, err)

		httpErr, ok := err.(*apierrors.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
		assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
	})

	t.Run("UserRevokeOAuthGrant rejects OAuth client session", func(t *testing.T) {
		ctx, req := createOAuthContext("", "")
		w := httptest.NewRecorder()

		err := server.UserRevokeOAuthGrant(w, req.WithContext(ctx))
		require.Error(t, err)

		httpErr, ok := err.(*apierrors.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
		assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
	})
}
