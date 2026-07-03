package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const IssuerFacebook = "https://www.facebook.com"

const (
	defaultFacebookAuthBase  = "www.facebook.com"
	defaultFacebookTokenBase = "graph.facebook.com" //#nosec G101 -- Not a secret value.
	defaultFacebookAPIBase   = "graph.facebook.com"
)

type facebookProvider struct {
	*oauth2.Config
	ProfileURL    string
	DebugTokenURL string
}

type facebookDebugToken struct {
	Data struct {
		AppID   string `json:"app_id"`
		Type    string `json:"type"`
		IsValid bool   `json:"is_valid"`
		UserID  string `json:"user_id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"data"`
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
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultFacebookAuthBase)
	tokenHost := chooseHost(ext.URL, defaultFacebookTokenBase)
	apiHost := chooseHost(ext.URL, defaultFacebookAPIBase)
	profileURL := apiHost + "/me?fields=email,first_name,last_name,name,picture"
	debugTokenURL := apiHost + "/debug_token"

	oauthScopes := []string{
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &facebookProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/dialog/oauth",
				TokenURL: tokenHost + "/oauth/access_token",
			},
			Scopes: oauthScopes,
		},
		ProfileURL:    profileURL,
		DebugTokenURL: debugTokenURL,
	}, nil
}

// VerifyAccessToken confirms that the given access token was issued for this
// Facebook app and is still valid. This is required when signing in with an
// access token obtained on the client (for example a native Android login),
// to mitigate access token substitution where a token minted for another app
// could otherwise be replayed against this one.
func (p facebookProvider) VerifyAccessToken(ctx context.Context, accessToken string) (string, error) {
	// The app access token authenticates the /debug_token call. It is sent as a
	// bearer token rather than a query parameter so the client secret is not
	// captured by URL loggers.
	appAccessToken := p.Config.ClientID + "|" + p.Config.ClientSecret

	query := url.Values{}
	query.Set("input_token", accessToken)
	requestURL := p.DebugTokenURL + "?" + query.Encode()

	var debugToken facebookDebugToken
	if err := makeRequest(ctx, &oauth2.Token{AccessToken: appAccessToken}, p.Config, requestURL, &debugToken); err != nil {
		// /debug_token requires input_token in the query string, so strip the URL
		// from transport errors to avoid leaking the access token into logs.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return "", fmt.Errorf("facebook: could not reach the token debug endpoint: %w", urlErr.Err)
		}
		return "", err
	}

	if !debugToken.Data.IsValid {
		return "", fmt.Errorf("facebook: access token is not valid: %s", debugToken.Data.Error.Message)
	}

	if debugToken.Data.AppID != p.Config.ClientID {
		return "", fmt.Errorf("facebook: access token was not issued for this app")
	}

	if debugToken.Data.Type != "USER" {
		return "", fmt.Errorf("facebook: access token is not a user token (type=%q)", debugToken.Data.Type)
	}

	if debugToken.Data.UserID == "" {
		return "", fmt.Errorf("facebook: access token does not contain a user id")
	}

	return debugToken.Data.UserID, nil
}

func (p facebookProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p facebookProvider) RequiresPKCE() bool {
	return false
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

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:   p.ProfileURL,
		Subject:  u.ID,
		Name:     strings.TrimSpace(u.FirstName + " " + u.LastName),
		NickName: u.Alias,
		Picture:  u.Avatar.Data.URL,

		// To be deprecated
		Slug:       u.Alias,
		AvatarURL:  u.Avatar.Data.URL,
		FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
		ProviderId: u.ID,
	}

	return data, nil
}
