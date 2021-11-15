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
	defaultFacebookAuthBase  = "www.facebook.com"
	defaultFacebookTokenBase = "graph.facebook.com"
	defaultFacebookAPIBase   = "graph.facebook.com"
)

type facebookProvider struct {
	*oauth2.Config
	ProfileURL string
}

type facebookUser struct {
	ID        string `json:"id"`
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

// NewFacebookProvider creates a Facebook account provider.
func NewFacebookProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultFacebookAuthBase)
	tokenHost := chooseHost(ext.URL, defaultFacebookTokenBase)
	profileURL := chooseHost(ext.URL, defaultFacebookAPIBase) + "/me?fields=email,first_name,last_name,name,picture"

	oauthScopes := []string{
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &facebookProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/dialog/oauth",
				TokenURL: tokenHost + "/oauth/access_token",
			},
			Scopes: oauthScopes,
		},
		ProfileURL: profileURL,
	}, nil
}

func (p facebookProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(oauth2.NoContext, code)
}

func (p facebookProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	hash := hmac.New(sha256.New, []byte(p.Config.ClientSecret))
	hash.Write([]byte(tok.AccessToken))
	appsecretProof := hex.EncodeToString(hash.Sum(nil))

	var u facebookUser
	url := p.ProfileURL + "&appsecret_proof=" + appsecretProof
	if err := makeRequest(ctx, tok, p.Config, url, &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Facebook provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        p.ProfileURL,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			NickName:      u.Alias,
			Email:         u.Email,
			EmailVerified: true, // if email is returned, the email is verified by facebook already
			Picture:       u.Avatar.Data.URL,

			// To be deprecated
			Slug:       u.Alias,
			AvatarURL:  u.Avatar.Data.URL,
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}, nil
}
