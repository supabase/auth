package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func (ts *ExternalTestSuite) TestSignupExternalSnapchat() {
	server := SnapchatTestSignupSetup(ts, nil, nil, "", "")
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=snapchat", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := u.Query()
	ts.Equal(ts.Config.External.Snapchat.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Snapchat.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
}

func SnapchatTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/oauth2/token":
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Notion.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"snapchat_token","expires_in":100000}`)
		case "/v1/me":
			*userCount++
			ts.Contains(r.Header, "Authorization")
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown snapchat oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Snapchat.URL = server.URL

	return server
}
