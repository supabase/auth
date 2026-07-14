package oauthserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (ts *OAuthClientTestSuite) mintApprovedCode(clientID, userID uuid.UUID) string {
	auth := models.NewOAuthServerAuthorization(models.NewOAuthServerAuthorizationParams{
		ClientID:    clientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "profile",
		TTL:         time.Hour,
	})
	require.NoError(ts.T(), models.CreateOAuthServerAuthorization(ts.DB, auth))
	require.NoError(ts.T(), auth.SetUser(ts.DB, userID))
	require.NoError(ts.T(), auth.Approve(ts.DB))
	return *auth.AuthorizationCode
}

func (ts *OAuthClientTestSuite) TestAuthCodeReplayRaceCS() {
	ctx, cancel := context.WithCancel(ts.T().Context())
	defer cancel()

	client, _ := ts.createTestOAuthClient()
	ctx = shared.WithOAuthServerClient(ctx, client)
	user := ts.createTestUser("replay-race@example.com")
	code := ts.mintApprovedCode(client.ID, user.ID)

	const count = 10
	errCh := make(chan error, count)
	initCh := make(chan struct{}, count)
	startCh := make(chan struct{})
	startFn := sync.OnceFunc(func() { close(startCh) })
	defer startFn()

	for range count {
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/oauth/token", nil)
			params := &OAuthTokenParams{Code: code, GrantType: GrantTypeAuthorizationCode}

			select {
			case <-ctx.Done():
				return
			case initCh <- struct{}{}:
			}
			<-startCh

			err := ts.Server.handleAuthorizationCodeGrant(ctx, rec, req, params)
			select {
			case <-ctx.Done():
			case errCh <- err:
			}
		}()
	}

	// Wait for goroutines to be ready
	for range count {
		select {
		case <-ctx.Done():
			ts.T().Fatal(ctx.Err())
		case <-initCh:
		}
	}

	// Start goroutines
	startFn()

	// Collect errors
	var errs []error
	for range count {
		select {
		case <-ctx.Done():
			ts.T().Fatal(ctx.Err())
		case err := <-errCh:
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	assert.Equal(ts.T(), count-1, len(errs),
		"authorization code must be single-use, got %d", count-len(errs))

	for _, err := range errs {
		e := new(apierrors.OAuthError)
		assert.True(ts.T(), errors.As(err, &e), "expected error type %T; got %T", e, err)
		assert.Equal(ts.T(), e.Err, "invalid_grant")
		assert.Equal(ts.T(), e.Description, "Invalid authorization code")
	}

	_, err := models.FindOAuthServerAuthorizationByCode(ts.DB, code)
	assert.True(ts.T(), models.IsNotFoundError(err),
		"authorization code should be consumed after redemption")
}
