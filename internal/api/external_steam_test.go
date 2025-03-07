package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

func (ts *ExternalTestSuite) TestSignupExternalSteam() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=steam", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	
	q := u.Query()
	ts.Equal("checkid_setup", q.Get("openid.mode"))
	ts.Equal("http://specs.openid.net/auth/2.0", q.Get("openid.ns"))
	ts.Equal(ts.Config.External.Steam.Realm, q.Get("openid.realm"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("steam", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
} 