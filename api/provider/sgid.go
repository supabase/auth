package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

// sgID

const (
	defaultSgidAuthBase = "api.id.gov.sg/v1"
	defaultSgidAPIBase  = "api.id.gov.sg"
)

type sgidProvider struct {
	*oauth2.Config
	APIHost string
}

type sgidUser struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
}

type sgidPayload struct {
	Sub       string            `json:"sub"`
	Key     	string            `json:"key"`
	Data      map[string]interface{} `json:"data"`
}

// NewSgidProvider creates a sgID/Singpass account provider.
func NewSgidProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultSgidAuthBase)
	apiHost := chooseHost(ext.URL, defaultSgidAPIBase)
	if !strings.HasSuffix(apiHost, defaultSgidAPIBase) {
		apiHost += "/v1"
	}

	oauthScopes := []string{
		"openid",
		"myinfo.email", 
		"myinfo.name",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &sgidProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth/authorize",
				TokenURL: authHost + "/oauth/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (g sgidProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g sgidProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u sgidPayload
	fmt.Printf("%+v\n", tok)
	if err := makeRequest(ctx, tok, g.Config, g.APIHost+"/userinfo", &u); err != nil {
		return nil, err
	}

	fmt.Printf("%+v\n", u)

	// TODO: decrypt u.key (AES-128-GCM symmetric key that is encrypted with your RSA-2048 public key) 
	// & decrypt u.data (Encrypted Payload (Refer to “Decrypt the sgID encrypted payload” for more information))
	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:            g.APIHost,
			Subject:           u.Sub,
			// Name:           u.Name,
		},
	}

	return data, nil
}
