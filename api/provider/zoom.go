package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultZoomAuthBase = "zoom.us"
	defaultZoomAPIBase  = "api.zoom.us"
)

type zoomProvider struct {
	*oauth2.Config
	APIPath string
}

type zoomUser struct {
	ID            string `json:"id"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	EmailVerified int    `json:"verified"`
	LoginType     string `json:"login_type"`
	AvatarURL     string `json:"pic_url"`
}

// NewZoomProvider creates a Zoom account provider.
func NewZoomProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultZoomAPIBase) + "/v2"
	authPath := chooseHost(ext.URL, defaultZoomAuthBase) + "/oauth"

	return &zoomProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/authorize",
				TokenURL: authPath + "/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g zoomProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g zoomProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u zoomUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/users/me", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Zoom provider")
	}

	verified := true

	// A login_type of "100" refers to email-based logins, not oauth.
	// A user is verified (type 1) only if they received an email when their profile was created and confirmed the link.
	// A zoom user will only be sent an email confirmation link if they signed up using their zoom work email and not oauth.
	// See: https://devforum.zoom.us/t/how-to-determine-if-a-zoom-user-actually-owns-their-email-address/44430
	if u.LoginType == "100" && u.EmailVerified == 0 {
		verified = false
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			Picture:       u.AvatarURL,
			Email:         u.Email,
			EmailVerified: verified,

			// To be deprecated
			AvatarURL:  u.AvatarURL,
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: verified,
			Primary:  true,
		}},
	}, nil
}
