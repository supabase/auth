package oauthserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/shared"
)

func (ts *OAuthClientTestSuite) TestOAuthTokenResponsesAreNotCached() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("no-store@example.com")

	token := func(code string) (*httptest.ResponseRecorder, error) {
		body, err := json.Marshal(map[string]string{"grant_type": GrantTypeAuthorizationCode, "code": code})
		require.NoError(ts.T(), err)
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(shared.WithOAuthServerClient(req.Context(), client))
		w := httptest.NewRecorder()
		return w, ts.Server.OAuthToken(w, req)
	}

	w, err := token(ts.mintApprovedCode(client.ID, user.ID))
	require.NoError(ts.T(), err)
	require.Contains(ts.T(), w.Body.String(), "access_token")
	require.Equal(ts.T(), "no-store", w.Header().Get("Cache-Control"))

	// An error response is written to the same ResponseWriter, so it keeps the header.
	w, err = token("not-a-real-code")
	require.Error(ts.T(), err)
	require.Equal(ts.T(), "no-store", w.Header().Get("Cache-Control"))
}
