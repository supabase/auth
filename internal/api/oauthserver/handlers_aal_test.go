package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (ts *OAuthClientTestSuite) TestAuthCodeGrantInheritsApprovingSessionAAL() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("aal-inherit@example.com")

	approving, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.DB.Create(approving))
	require.NoError(ts.T(), models.AddClaimToSession(ts.DB, approving.ID, models.PasswordGrant))
	require.NoError(ts.T(), models.AddClaimToSession(ts.DB, approving.ID, models.TOTPSignIn))
	require.NoError(ts.T(), approving.UpdateAALAndAssociatedFactor(ts.DB, models.AAL2, nil))

	auth := models.NewOAuthServerAuthorization(models.NewOAuthServerAuthorizationParams{
		ClientID:    client.ID,
		RedirectURI: "https://example.com/callback",
		Scope:       "profile",
		TTL:         time.Hour,
	})
	require.NoError(ts.T(), models.CreateOAuthServerAuthorization(ts.DB, auth))
	require.NoError(ts.T(), auth.SetUser(ts.DB, user.ID))
	require.NoError(ts.T(), auth.Approve(ts.DB, &approving.ID))

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	ctx := shared.WithOAuthServerClient(req.Context(), client)
	w := httptest.NewRecorder()
	params := &OAuthTokenParams{GrantType: GrantTypeAuthorizationCode, Code: *auth.AuthorizationCode}
	require.NoError(ts.T(), ts.Server.handleAuthorizationCodeGrant(ctx, w, req.WithContext(ctx), params))

	sessionID := uuid.FromStringOrNil(w.Header().Get("sb-auth-session-id"))
	session, err := models.FindSessionByID(ts.DB, sessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), models.AAL2.String(), session.GetAAL())

	aal, amr, err := session.CalculateAALAndAMR(user)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), models.AAL2, aal)
	methods := []string{}
	for _, entry := range amr {
		methods = append(methods, entry.Method)
	}
	require.ElementsMatch(ts.T(), []string{"oauth_provider/authorization_code", "password", "totp"}, methods)
}
