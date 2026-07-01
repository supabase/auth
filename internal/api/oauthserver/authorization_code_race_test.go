package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (ts *OAuthClientTestSuite) TestAuthorizationCodeSingleUseUnderConcurrency() {
	client, _ := ts.createTestOAuthClient()
	client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	require.NoError(ts.T(), ts.DB.UpdateOnly(client, "grant_types"))

	user := ts.createTestUser("code-race@example.com")

	verifier := "code-race-verifier-0123456789012345678901234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	method := "s256"

	code := "code-race-single-use-abcdef0123456789"
	redirectURI := "https://example.com/callback"

	auth := &models.OAuthServerAuthorization{
		ID:                  uuid.Must(uuid.NewV4()),
		AuthorizationID:     uuid.Must(uuid.NewV4()).String(),
		ClientID:            client.ID,
		UserID:              &user.ID,
		RedirectURI:         redirectURI,
		Scope:               "email", // non-openid, skips ID-token signing
		CodeChallenge:       &challenge,
		CodeChallengeMethod: &method,
		ResponseType:        models.OAuthServerResponseTypeCode,
		Status:              models.OAuthServerAuthorizationApproved,
		AuthorizationCode:   &code,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	require.NoError(ts.T(), ts.DB.Create(auth))

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	tokens := map[string]bool{}
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("code_verifier", verifier)
			form.Set("redirect_uri", redirectURI)

			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
			w := httptest.NewRecorder()

			<-start
			if err := ts.Server.OAuthToken(w, req); err != nil || w.Code != http.StatusOK {
				return
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				return
			}
			if tok, _ := resp["access_token"].(string); tok != "" {
				mu.Lock()
				tokens[tok] = true
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Equal(ts.T(), 1, len(tokens),
		"one authorization code must not mint more than one token, got %d", len(tokens))
}
