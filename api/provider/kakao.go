package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultKakaoApiBase = "kauth.kakao.com"
	defaultKakaoAPIBase = "kapi.kakao.com"
)

type kakaoProvider struct {
	*oauth2.Config
	APIPath string
}

type kakaoUser struct {
	ID           string `json:"id"`
	KakaoAccount struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"is_email_verifieds"`
		Name          string `json:"name"`
		Profile       struct {
			Nickname  string `json:"nickname"`
			AvatarURL string `json:"profile_image_url"`
		} `json:"profile"`
	} `json:"kakao_account"`
}

// NewKakaoProvider creates a Kakao account provider.
func NewKakaoProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultKakaoApiBase)
	authPath := chooseHost(ext.URL, defaultKakaoApiBase)

	oauthScopes := []string{
		"profile_image",
		"profile_nickname",
		"account_email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &kakaoProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/oauth/authorize",
				TokenURL: apiPath + "/oauth/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g kakaoProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g kakaoProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u kakaoUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/v2/user/me", &u); err != nil {
		return nil, err
	}
	fmt.Printf("%+v\n", u)

	if u.KakaoAccount.Email == "" {
		return nil, errors.New("Unable to find email with Kakao provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          u.KakaoAccount.Name,
			Picture:       u.KakaoAccount.Profile.AvatarURL,
			Email:         u.KakaoAccount.Email,
			EmailVerified: u.KakaoAccount.EmailVerified,
		},
		Emails: []Email{{
			Email:    u.KakaoAccount.Email,
			Verified: u.KakaoAccount.EmailVerified,
			Primary:  true,
		}},
	}, nil
}
