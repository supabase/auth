package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func createOAuthTestContext(userID uuid.UUID, clientID uuid.UUID, scopes string) context.Context {
	sessID := uuid.Must(uuid.NewV4())
	scopesStr := scopes
	session := &models.Session{
		ID:            sessID,
		UserID:        userID,
		OAuthClientID: &clientID,
		Scopes:        &scopesStr,
	}
	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  userID.String(),
			Audience: jwt.ClaimStrings{"authenticated"},
		},
		SessionId: sessID.String(),
		ClientID:  clientID.String(),
		Scope:     scopes,
	}
	token := &jwt.Token{
		Claims: claims,
	}
	ctx := context.Background()
	ctx = withToken(ctx, token)
	ctx = withSession(ctx, session)
	ctx = shared.WithSession(ctx, session)
	return ctx
}

func createNormalUserTestContext(userID uuid.UUID) context.Context {
	sessID := uuid.Must(uuid.NewV4())
	session := &models.Session{
		ID:            sessID,
		UserID:        userID,
		OAuthClientID: nil,
	}
	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  userID.String(),
			Audience: jwt.ClaimStrings{"authenticated"},
		},
		SessionId: sessID.String(),
		ClientID:  "",
	}
	token := &jwt.Token{
		Claims: claims,
	}
	ctx := context.Background()
	ctx = withToken(ctx, token)
	ctx = withSession(ctx, session)
	ctx = shared.WithSession(ctx, session)
	return ctx
}

func TestSession_IsOAuth(t *testing.T) {
	var nilSession *models.Session
	assert.False(t, nilSession.IsOAuth())

	sessionWithoutOAuth := &models.Session{OAuthClientID: nil}
	assert.False(t, sessionWithoutOAuth.IsOAuth())

	nilUUID := uuid.Nil
	sessionWithNilUUID := &models.Session{OAuthClientID: &nilUUID}
	assert.False(t, sessionWithNilUUID.IsOAuth())

	validUUID := uuid.Must(uuid.NewV4())
	sessionWithValidOAuth := &models.Session{OAuthClientID: &validUUID}
	assert.True(t, sessionWithValidOAuth.IsOAuth())
}

func TestIsOAuthClientRequest(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	// 1. Empty context
	assert.False(t, api.isOAuthClientRequest(context.Background()))

	// 2. Normal user context
	normalCtx := createNormalUserTestContext(userID)
	assert.False(t, api.isOAuthClientRequest(normalCtx))

	// 3. Context with OAuth claims and OAuth session
	oauthCtx := createOAuthTestContext(userID, clientID, "openid email")
	assert.True(t, api.isOAuthClientRequest(oauthCtx))

	// 4. Context with only claims having ClientID
	claimsOnlyToken := &jwt.Token{
		Claims: &AccessTokenClaims{ClientID: clientID.String()},
	}
	claimsOnlyCtx := withToken(context.Background(), claimsOnlyToken)
	assert.True(t, api.isOAuthClientRequest(claimsOnlyCtx))

	// 5. Context with only session having OAuthClientID
	sessionOnlySess := &models.Session{OAuthClientID: &clientID}
	sessionOnlyCtx := withSession(context.Background(), sessionOnlySess)
	assert.True(t, api.isOAuthClientRequest(sessionOnlyCtx))
}

func TestRequireNotOAuthClientMiddleware(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	// Test case 1: Regular end-user request passes
	normalCtx := createNormalUserTestContext(userID)
	req := httptest.NewRequest(http.MethodPut, "/user", nil).WithContext(normalCtx)
	w := httptest.NewRecorder()

	outCtx, err := api.requireNotOAuthClient(w, req)
	assert.NoError(t, err)
	assert.NotNil(t, outCtx)

	// Test case 2: OAuth client token request is rejected with 403 Forbidden
	oauthCtx := createOAuthTestContext(userID, clientID, "openid")
	oauthReq := httptest.NewRequest(http.MethodPut, "/user", nil).WithContext(oauthCtx)
	oauthW := httptest.NewRecorder()

	_, err = api.requireNotOAuthClient(oauthW, oauthReq)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
}

func TestSanitizeUserForOAuth(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())
	now := time.Now()

	createBaseUser := func() *models.User {
		return &models.User{
			ID:               userID,
			Aud:              "authenticated",
			Role:             "authenticated",
			Email:            storage.NullString("user@example.com"),
			EmailConfirmedAt: &now,
			Phone:            storage.NullString("+1234567890"),
			PhoneConfirmedAt: &now,
			UserMetaData: models.JSONMap{
				"full_name": "Test User",
			},
			AppMetaData: models.JSONMap{
				"provider": "email",
				"role":     "superadmin",
			},
			Factors: []models.Factor{
				{ID: uuid.Must(uuid.NewV4()), FactorType: models.TOTP, Status: models.FactorStateVerified.String()},
			},
			Identities: []models.Identity{
				{ID: uuid.Must(uuid.NewV4()), Provider: "email"},
			},
		}
	}

	t.Run("nil user returns nil", func(t *testing.T) {
		assert.Nil(t, api.sanitizeUserForOAuth(context.Background(), nil))
	})

	t.Run("openid only: strips email, phone, user_metadata, and internal security fields", func(t *testing.T) {
		ctx := createOAuthTestContext(userID, clientID, "openid")
		sanitized := api.sanitizeUserForOAuth(ctx, createBaseUser())

		require.NotNil(t, sanitized)
		assert.Equal(t, userID, sanitized.ID)
		assert.Empty(t, sanitized.Email.String())
		assert.Nil(t, sanitized.EmailConfirmedAt)
		assert.Empty(t, sanitized.Phone.String())
		assert.Nil(t, sanitized.PhoneConfirmedAt)
		assert.Nil(t, sanitized.UserMetaData)
		assert.Nil(t, sanitized.AppMetaData, "AppMetaData must always be stripped for OAuth clients")
		assert.Nil(t, sanitized.Identities, "Identities must always be stripped for OAuth clients")
		assert.Nil(t, sanitized.Factors, "Factors must always be stripped for OAuth clients")
	})

	t.Run("openid email: includes email but strips phone, metadata, and security fields", func(t *testing.T) {
		ctx := createOAuthTestContext(userID, clientID, "openid email")
		sanitized := api.sanitizeUserForOAuth(ctx, createBaseUser())

		require.NotNil(t, sanitized)
		assert.Equal(t, "user@example.com", sanitized.Email.String())
		assert.NotNil(t, sanitized.EmailConfirmedAt)
		assert.Empty(t, sanitized.Phone.String())
		assert.Nil(t, sanitized.UserMetaData)
		assert.Nil(t, sanitized.AppMetaData)
		assert.Nil(t, sanitized.Identities)
		assert.Nil(t, sanitized.Factors)
	})

	t.Run("openid email profile: includes email and user_metadata", func(t *testing.T) {
		ctx := createOAuthTestContext(userID, clientID, "openid email profile")
		sanitized := api.sanitizeUserForOAuth(ctx, createBaseUser())

		require.NotNil(t, sanitized)
		assert.Equal(t, "user@example.com", sanitized.Email.String())
		assert.NotNil(t, sanitized.UserMetaData)
		assert.Equal(t, "Test User", sanitized.UserMetaData["full_name"])
		assert.Empty(t, sanitized.Phone.String())
		assert.Nil(t, sanitized.AppMetaData)
		assert.Nil(t, sanitized.Identities)
		assert.Nil(t, sanitized.Factors)
	})

	t.Run("openid phone: includes phone but strips email and user_metadata", func(t *testing.T) {
		ctx := createOAuthTestContext(userID, clientID, "openid phone")
		sanitized := api.sanitizeUserForOAuth(ctx, createBaseUser())

		require.NotNil(t, sanitized)
		assert.Empty(t, sanitized.Email.String())
		assert.Equal(t, "+1234567890", sanitized.Phone.String())
		assert.NotNil(t, sanitized.PhoneConfirmedAt)
		assert.Nil(t, sanitized.UserMetaData)
		assert.Nil(t, sanitized.AppMetaData)
		assert.Nil(t, sanitized.Identities)
		assert.Nil(t, sanitized.Factors)
	})
}

func TestUserGet_OAuthClientScopeFiltering(t *testing.T) {
	api := &API{
		config: &conf.GlobalConfiguration{
			JWT: conf.JWTConfiguration{
				Aud: "authenticated",
			},
		},
	}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	user := &models.User{
		ID:    userID,
		Aud:   "authenticated",
		Email: storage.NullString("test@example.com"),
		UserMetaData: models.JSONMap{
			"nickname": "dev",
		},
		AppMetaData: models.JSONMap{
			"role": "admin",
		},
	}

	// Request with openid only
	ctx := createOAuthTestContext(userID, clientID, "openid")
	ctx = withUser(ctx, user)

	req := httptest.NewRequest(http.MethodGet, "/user", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	err := api.UserGet(w, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp models.User
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, userID, resp.ID)
	assert.Empty(t, resp.Email.String(), "Email should be stripped without email scope")
	assert.Nil(t, resp.UserMetaData, "UserMetaData should be stripped without profile scope")
	assert.Nil(t, resp.AppMetaData, "AppMetaData should always be stripped for OAuth clients")
}

func TestUserUpdate_OAuthClientRejected(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	ctx := createOAuthTestContext(userID, clientID, "openid email")
	req := httptest.NewRequest(http.MethodPut, "/user", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	err := api.UserUpdate(w, req)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
}

func TestEnrollFactor_OAuthClientRejected(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	ctx := createOAuthTestContext(userID, clientID, "openid")
	req := httptest.NewRequest(http.MethodPost, "/factors", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	err := api.EnrollFactor(w, req)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
}

func TestIdentity_OAuthClientRejected(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	ctx := createOAuthTestContext(userID, clientID, "openid")

	// DeleteIdentity
	req := httptest.NewRequest(http.MethodDelete, "/user/identities/some-id", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	err := api.DeleteIdentity(w, req)
	require.Error(t, err)
	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)

	// LinkIdentity
	reqLink := httptest.NewRequest(http.MethodGet, "/user/identities/authorize", nil).WithContext(ctx)
	wLink := httptest.NewRecorder()
	errLink := api.LinkIdentity(wLink, reqLink)
	require.Error(t, errLink)
	httpErrLink, ok := errLink.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErrLink.HTTPStatus)
}

func TestReauthenticate_OAuthClientRejected(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	ctx := createOAuthTestContext(userID, clientID, "openid")
	req := httptest.NewRequest(http.MethodGet, "/reauthenticate", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	err := api.Reauthenticate(w, req)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
}

func TestLogout_OAuthClientRejected(t *testing.T) {
	api := &API{}
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	ctx := createOAuthTestContext(userID, clientID, "openid")
	req := httptest.NewRequest(http.MethodPost, "/logout", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	err := api.Logout(w, req)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)
}

func TestRequirePasskeyManagementAAL_OAuthClientRejected(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())

	userWithoutMFA := &models.User{ID: userID}

	oauthSession := &models.Session{
		ID:            uuid.Must(uuid.NewV4()),
		UserID:        userID,
		OAuthClientID: &clientID,
	}

	err := requirePasskeyManagementAAL(userWithoutMFA, oauthSession)
	require.Error(t, err)

	httpErr, ok := err.(*apierrors.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.HTTPStatus)
	assert.Equal(t, apierrors.ErrorCodeNoAuthorization, httpErr.ErrorCode)

	// Normal session without MFA should pass
	normalSession := &models.Session{
		ID:            uuid.Must(uuid.NewV4()),
		UserID:        userID,
		OAuthClientID: nil,
	}
	assert.NoError(t, requirePasskeyManagementAAL(userWithoutMFA, normalSession))
}
