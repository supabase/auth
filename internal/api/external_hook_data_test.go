package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

// The OAuth leg is the only one where the caller's value has to outlive the
// request that carried it: it is written when the flow begins and read back
// when the provider returns, a redirect and an unknown amount of time later.
// These cover the two ends of that, plus the one thing that would leak it.

func (ts *ExternalTestSuite) TestAuthorizeStoresHookData() {
	req := httptest.NewRequest(
		http.MethodGet,
		"http://localhost/authorize?provider=google&hook_data=opaque-value",
		nil)
	req.Header.Set("Referer", "https://example.netlify.com/admin")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	location, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)

	// Everything left in the query is appended to the provider's authorize URL,
	// so the value must be removed on the way out. Sending an application's
	// private data to Google would be a quiet leak on every sign-in.
	ts.Require().Equal("", location.Query().Get("hook_data"))
	ts.Require().False(strings.Contains(location.RawQuery, "opaque-value"))

	state := location.Query().Get("state")
	ts.Require().NotEmpty(state)

	flowState, err := models.FindFlowStateByID(ts.API.db, state)
	ts.Require().NoError(err)
	ts.Require().NotNil(flowState.HookData)
	ts.Require().Equal("opaque-value", *flowState.HookData)
}

func (ts *ExternalTestSuite) TestAuthorizeWithoutHookData() {
	w := performAuthorizationRequest(ts, "google", "")
	ts.Require().Equal(http.StatusFound, w.Code)

	location, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)

	flowState, err := models.FindFlowStateByID(ts.API.db, location.Query().Get("state"))
	ts.Require().NoError(err)
	ts.Require().Nil(flowState.HookData)
}

func (ts *ExternalTestSuite) TestAuthorizeRejectsOversizeHookData() {
	req := httptest.NewRequest(
		http.MethodGet,
		"http://localhost/authorize?provider=google&hook_data="+
			strings.Repeat("x", utilities.MaxHookDataLength+1),
		nil)
	req.Header.Set("Referer", "https://example.netlify.com/admin")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	// Refused rather than truncated: a value silently cut in half would be
	// rejected by whatever hook reads it, far from where it was mangled.
	ts.Require().NotEqual(http.StatusFound, w.Code)
}

// The other end. The callback restores the value into the request context,
// which is where NewMetadata reads it from when it builds a hook payload.
func (ts *ExternalTestSuite) TestCallbackRestoresHookData() {
	hookData := "opaque-value"
	flowState, err := models.NewFlowState(models.FlowStateParams{
		ProviderType:         "google",
		AuthenticationMethod: models.OAuth,
		HookData:             hookData,
		Referrer:             ts.Config.SiteURL,
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(flowState))

	ctx, err := ts.API.loadExternalStateFromUUID(
		context.Background(), ts.API.db, flowState.ID)
	ts.Require().NoError(err)
	ts.Require().Equal(hookData, utilities.GetHookData(ctx))
}

func (ts *ExternalTestSuite) TestCallbackWithoutHookData() {
	flowState, err := models.NewFlowState(models.FlowStateParams{
		ProviderType:         "google",
		AuthenticationMethod: models.OAuth,
		Referrer:             ts.Config.SiteURL,
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(flowState))

	ctx, err := ts.API.loadExternalStateFromUUID(
		context.Background(), ts.API.db, flowState.ID)
	ts.Require().NoError(err)
	ts.Require().Equal("", utilities.GetHookData(ctx))
}

// Consumed means finished with. The hook for this request has already run and
// nothing reads the value again, so it has no business remaining in the row --
// nor in any backup taken afterwards.
//
// PKCE deliberately: the implicit flow destroys the whole flow state at the
// callback, so it is the only one where anything could linger.
func (ts *ExternalTestSuite) TestCallbackClearsHookDataOnceConsumed() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	codeVerifier := "4a9505b9-0857-42bb-ab3c-098b4d28ddc2"
	hashed := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hashed[:])

	req := httptest.NewRequest(
		http.MethodGet,
		"http://localhost/authorize?provider=github&hook_data=opaque-value"+
			"&code_challenge="+codeChallenge+"&code_challenge_method=s256",
		nil)
	req.Header.Set("Referer", "https://example.supabase.com/admin")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	location, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	state := location.Query().Get("state")

	// It is there while the round trip is in progress -- that is the whole
	// point of storing it.
	pending, err := models.FindFlowStateByID(ts.API.db, state)
	ts.Require().NoError(err)
	ts.Require().NotNil(pending.HookData)

	callback, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	v := callback.Query()
	v.Set("code", code)
	v.Set("state", state)
	callback.RawQuery = v.Encode()

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, callback.String(), nil))
	ts.Require().Equal(http.StatusFound, w.Code)

	// And gone once it is not.
	settled, err := models.FindFlowStateByID(ts.API.db, state)
	ts.Require().NoError(err)
	ts.Require().Nil(settled.HookData)
	ts.Require().NotNil(settled.UserID, "the callback should have claimed the flow state")
}
