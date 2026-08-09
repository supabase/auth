package api

import (
	"context"
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
