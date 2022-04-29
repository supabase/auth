package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt"
)

const (
	orcidUser           string = `{"data":[{"id":"twitchTestId","login":"Orcid user","display_name":"Orcid user","type":"","broadcaster_type":"","description":"","profile_image_url":"https://s.gravatar.com/avatar/23463b99b62a72f26ed677cc556c44e8","offline_image_url":"","email":"twitch@example.com"}]}`
	orcidUserWrongEmail string = `{"data":[{"id":"twitchTestId","login":"Orcid user","display_name":"Orcid user","type":"","broadcaster_type":"","description":"","profile_image_url":"https://s.gravatar.com/avatar/23463b99b62a72f26ed677cc556c44e8","offline_image_url":"","email":"other@example.com"}]}`
)

func (ts *ExternalTestSuite) TestSignupExternalOrcid() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=orcid", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Orcid.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Orcid.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("/authenticate", q.Get("scope"))
	ts.NotEqual("", q.Get("orcid"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("orcid", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}
