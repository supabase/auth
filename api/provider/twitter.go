package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultTwitterAuthBase = "twitter.com"
	defaultTwitterAPIBase  = "api.twitter.com"
)

type twitterProvider struct {
	*oauth2.Config
	ProfileURL string
}

type twitterUser struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Alias     string `json:"name"`
	Avatar    struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

// NewTwitterProvider creates a Twitter account provider.
func NewTwitterProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	authHost := chooseHost(ext.URL, defaultTwitterAuthBase)
	tokenHost := chooseHost(ext.URL, defaultTwitterAPIBase)
	profileURL := chooseHost(ext.URL, defaultTwitterAPIBase) + "/me?fields=email,first_name,last_name,name,picture"

	return &twitterProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "oauth/authorize",
				TokenURL: tokenHost + "/oauth2/request_token",
			},
			Scopes: []string{
				"email",
				scopes,
			},
		},
		ProfileURL: profileURL,
	}, nil
}

func (p twitterProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(oauth2.NoContext, code)
}

func (p twitterProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	hash := hmac.New(sha256.New, []byte(p.Config.ClientSecret))
	hash.Write([]byte(tok.AccessToken))
	appsecretProof := hex.EncodeToString(hash.Sum(nil))

	var u twitterUser
	url := p.ProfileURL + "&appsecret_proof=" + appsecretProof
	if err := makeRequest(ctx, tok, p.Config, url, &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Twitter provider")
	}

	return &UserProvidedData{
		Metadata: map[string]string{
			aliasKey:     u.Alias,
			nameKey:      strings.TrimSpace(u.FirstName + " " + u.LastName),
			avatarURLKey: u.Avatar.Data.URL,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}, nil
}
