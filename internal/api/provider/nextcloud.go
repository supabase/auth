package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

// Nextcloud

type nextcloudProvider struct {
	*oauth2.Config
	Host string
}

type nextcloudUser struct {
	Email            string   `json:"email"`
	Name             string   `json:"displayname"`
	AdditionalEmails []string `json:"additional_mail"`
	ID               string   `json:"id"`
	Website          string   `json:"website"`
	Phone            string   `json:"phone"`
	Locale           string   `json:"locale"`
}

type nextcloudUserResponse struct {
	OCS struct {
		Data nextcloudUser `json:"data"`
	} `json:"ocs"`
}

// NewNextcloudProvider creates a Nextcloud account provider.
func NewNextcloudProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{}

	host := chooseHost(ext.URL, "")
	return &nextcloudProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  host + "/index.php/apps/oauth2/authorize",
				TokenURL: host + "/index.php/apps/oauth2/api/v1/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: host,
	}, nil
}

func (g nextcloudProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g nextcloudProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var resp nextcloudUserResponse

	err := g.makeOCSRequest(ctx, tok, g.Host+"/ocs/v2.php/cloud/user", &resp)
	if err != nil {
		return nil, err
	}
	u := resp.OCS.Data
	data := &UserProvidedData{}

	// emails can be confirmed, but we don't have that information
	for _, e := range u.AdditionalEmails {
		if e != "" {
			data.Emails = append(data.Emails, Email{Email: e, Verified: true, Primary: false})
		}
	}

	if u.Email != "" {
		data.Emails = append(data.Emails, Email{Email: u.Email, Verified: true, Primary: true})
	}

	data.Metadata = &Claims{
		Issuer:  g.Host,
		Subject: u.ID,
		Name:    u.Name,
		Website: u.Website,
		Phone:   u.Phone,
		Locale:  u.Locale,

		// To be deprecated
		FullName:   u.Name,
		ProviderId: u.ID,
	}

	return data, nil
}

func (g nextcloudProvider) makeOCSRequest(ctx context.Context, tok *oauth2.Token, url string, dst interface{}) error {

	// Perform http request, because we neeed to set the Client-Id header
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return err
	}

	req.Header.Set("OCS-APIRequest", "true")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: defaultTimeout}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	bodyBytes, _ := io.ReadAll(res.Body)
	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return httpError(res.StatusCode, string(bodyBytes))
	}

	if err := json.NewDecoder(res.Body).Decode(dst); err != nil {
		return err
	}

	return nil

}
