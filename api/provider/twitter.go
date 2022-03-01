package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/mrjones/oauth"
	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultTwitterAPIBase = "api.twitter.com"
	requestURL            = "/oauth/request_token"
	authenticateURL       = "/oauth/authenticate"
	tokenURL              = "/oauth/access_token"
	endpointProfile       = "/1.1/account/verify_credentials.json"
)

// TwitterProvider stores the custom config for twitter provider
type TwitterProvider struct {
	ClientKey     string
	Secret        string
	CallbackURL   string
	AuthURL       string
	RequestToken  *oauth.RequestToken
	OauthVerifier string
	Consumer      *oauth.Consumer
	UserInfoURL   string
}

type twitterUser struct {
	UserName  string `json:"screen_name"`
	Name      string `json:"name"`
	AvatarURL string `json:"profile_image_url_https"`
	Email     string `json:"email"`
	ID        string `json:"id_str"`
}

// NewTwitterProvider creates a Twitter account provider.
func NewTwitterProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}
	authHost := chooseHost(ext.URL, defaultTwitterAPIBase)
	p := &TwitterProvider{
		ClientKey:   ext.ClientID,
		Secret:      ext.Secret,
		CallbackURL: ext.RedirectURI,
		UserInfoURL: authHost + endpointProfile,
	}
	p.Consumer = newConsumer(p, authHost)
	return p, nil
}

// GetOAuthToken is a stub method for OAuthProvider interface, unused in OAuth1.0 protocol
func (t TwitterProvider) GetOAuthToken(_ string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}

// GetUserData is a stub method for OAuthProvider interface, unused in OAuth1.0 protocol
func (t TwitterProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	return &UserProvidedData{}, nil
}

// FetchUserData retrieves the user's data from the twitter provider
func (t TwitterProvider) FetchUserData(ctx context.Context, tok *oauth.AccessToken) (*UserProvidedData, error) {
	var u twitterUser
	resp, err := t.Consumer.Get(
		t.UserInfoURL,
		map[string]string{"include_entities": "false", "skip_status": "true", "include_email": "true"},
		tok,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &UserProvidedData{}, fmt.Errorf("a %v error occurred with retrieving user from twitter", resp.StatusCode)
	}
	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&u)

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Twitter provider")
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:            t.UserInfoURL,
			Subject:           u.ID,
			Name:              u.Name,
			Picture:           u.AvatarURL,
			PreferredUsername: u.UserName,
			Email:             u.Email,
			EmailVerified:     true,

			// To be deprecated
			UserNameKey: u.UserName,
			FullName:    u.Name,
			AvatarURL:   u.AvatarURL,
			ProviderId:  u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}

	return data, nil
}

// AuthCodeURL fetches the request token from the twitter provider
func (t *TwitterProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	// we do nothing with the state here as the state is passed in the requestURL step
	requestToken, url, err := t.Consumer.GetRequestTokenAndUrl(t.CallbackURL + "?state=" + state)
	if err != nil {
		return ""
	}
	t.RequestToken = requestToken
	t.AuthURL = url
	return t.AuthURL
}

func newConsumer(provider *TwitterProvider, authHost string) *oauth.Consumer {
	c := oauth.NewConsumer(
		provider.ClientKey,
		provider.Secret,
		oauth.ServiceProvider{
			RequestTokenUrl:   authHost + requestURL,
			AuthorizeTokenUrl: authHost + authenticateURL,
			AccessTokenUrl:    authHost + tokenURL,
		},
	)
	return c
}

// Marshal encodes the twitter request token
func (t TwitterProvider) Marshal() string {
	b, _ := json.Marshal(t.RequestToken)
	return string(b)
}

// Unmarshal decodes the twitter request token
func (t TwitterProvider) Unmarshal(data string) (*oauth.RequestToken, error) {
	requestToken := &oauth.RequestToken{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(requestToken)
	return requestToken, err
}
