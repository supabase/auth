package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

func (ts *ExternalTestSuite) TestSignupExternalTikTok() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=tiktok", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.TikTok.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.TikTok.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("user.info.basic,video.list", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("tiktok", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}
