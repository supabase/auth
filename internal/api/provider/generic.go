package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

type genericProvider struct {
	*oauth2.Config
	APIURL          string
	UserDataMapping map[string]string
}

func (p genericProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p genericProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u map[string]interface{}

	// TODO flexible API call based on config

	// Perform http request manually, because we need to vary it based on the provider config
	req, err := http.NewRequest("GET", p.APIURL, nil)

	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Client-Id", p.ClientID)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from OAuth2 provider", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, err
	}

	// Read user data as specified in the JSON mapping
	mapping := p.UserDataMapping
	data := &UserProvidedData{
		Emails: []Email{
			{
				Email:    getFieldByPath(u, mapping["Email"], nil).(string),
				Verified: getFieldByPath(u, mapping["EmailVerified"], true).(bool),
				Primary:  true,
			},
		},
		Metadata: &Claims{
			Issuer:            p.APIURL,
			Subject:           getFieldByPath(u, mapping["Subject"], nil).(string),
			Name:              getFieldByPath(u, mapping["Name"], nil).(string),
			FamilyName:        getFieldByPath(u, mapping["FamilyName"], nil).(string),
			GivenName:         getFieldByPath(u, mapping["GivenName"], nil).(string),
			MiddleName:        getFieldByPath(u, mapping["MiddleName"], nil).(string),
			NickName:          getFieldByPath(u, mapping["NickName"], nil).(string),
			PreferredUsername: getFieldByPath(u, mapping["PreferredUsername"], nil).(string),
			Profile:           getFieldByPath(u, mapping["Profile"], nil).(string),
			Picture:           getFieldByPath(u, mapping["Picture"], nil).(string),
			Website:           getFieldByPath(u, mapping["Website"], nil).(string),
			Gender:            getFieldByPath(u, mapping["Gender"], nil).(string),
			Birthdate:         getFieldByPath(u, mapping["Birthdate"], nil).(string),
			ZoneInfo:          getFieldByPath(u, mapping["ZoneInfo"], nil).(string),
			Locale:            getFieldByPath(u, mapping["Locale"], nil).(string),
			UpdatedAt:         getFieldByPath(u, mapping["UpdatedAt"], nil).(string),
			Email:             getFieldByPath(u, mapping["Email"], nil).(string),
			EmailVerified:     getFieldByPath(u, mapping["EmailVerified"], true).(bool),
			Phone:             getFieldByPath(u, mapping["Email"], nil).(string),
			PhoneVerified:     getFieldByPath(u, mapping["EmailVerified"], true).(bool),
		},
	}

	// Read all optional claims
	for key, path := range mapping {
		value := getFieldByPath(u, path, "")
		if value == nil {
			fmt.Printf("Error extracting field %s: %v\n", key, err)
			continue
		}

		field := reflect.ValueOf(data.Metadata).Elem().FieldByName(key)
		if field.IsValid() && field.CanSet() {
			field.Set(reflect.ValueOf(value))
		}
	}
	return data, nil
}

func getFieldByPath(obj map[string]interface{}, path string, fallback interface{}) interface{} {
	value := obj

	for _, field := range strings.Split(path, ".") {
		fieldValue, ok := value[field]
		if !ok {
			return fallback
		}

		value, _ = fieldValue.(map[string]interface{})
	}

	return value
}

// NewGenericProvider creates an OAuth provider according to the config specified by the user
func NewGenericProvider(ext conf.GenericOAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := strings.Split(scopes, ",")

	return &genericProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  ext.AuthURL,
				TokenURL: ext.TokenURL,
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIURL:          ext.URL,
		UserDataMapping: ext.UserDataMapping,
	}, nil
}
