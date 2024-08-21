package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

type genericProvider struct {
	*oauth2.Config
	Issuer          string
	UserInfoURL     string
	UserDataMapping map[string]string
}

func (p genericProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p genericProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u map[string]interface{}

	// Perform http request manually, because we need to vary it based on the provider config
	req, err := http.NewRequest("GET", p.UserInfoURL, nil)

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
		return nil, fmt.Errorf("a %v error occurred with retrieving user from OAuth2 provider via %s", resp.StatusCode, p.UserInfoURL)
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

	email, err := getStringFieldByPath(u, mapping["Email"], "")
	if err != nil {
		return nil, err
	}

	emailVerified, err := getBooleanFieldByPath(u, mapping["EmailVerified"], email != "")
	if err != nil {
		return nil, err
	}

	emailPrimary, err := getBooleanFieldByPath(u, mapping["EmailPrimary"], email != "")
	if err != nil {
		return nil, err
	}

	issuer, err := getStringFieldByPath(u, mapping["Issuer"], p.Issuer)
	if err != nil {
		return nil, err
	}

	subject, err := getStringFieldByPath(u, mapping["Subject"], "")
	if err != nil {
		return nil, err
	}

	name, err := getStringFieldByPath(u, mapping["Name"], "")
	if err != nil {
		return nil, err
	}

	familyName, err := getStringFieldByPath(u, mapping["FamilyName"], "")
	if err != nil {
		return nil, err
	}

	givenName, err := getStringFieldByPath(u, mapping["GivenName"], "")
	if err != nil {
		return nil, err
	}

	middleName, err := getStringFieldByPath(u, mapping["MiddleName"], "")
	if err != nil {
		return nil, err
	}

	nickName, err := getStringFieldByPath(u, mapping["NickName"], "")
	if err != nil {
		return nil, err
	}

	preferredUsername, err := getStringFieldByPath(u, mapping["PreferredUsername"], "")
	if err != nil {
		return nil, err
	}

	profile, err := getStringFieldByPath(u, mapping["Profile"], "")
	if err != nil {
		return nil, err
	}

	picture, err := getStringFieldByPath(u, mapping["Picture"], "")
	if err != nil {
		return nil, err
	}

	website, err := getStringFieldByPath(u, mapping["Website"], "")
	if err != nil {
		return nil, err
	}

	gender, err := getStringFieldByPath(u, mapping["Gender"], "")
	if err != nil {
		return nil, err
	}

	birthdate, err := getStringFieldByPath(u, mapping["Birthdate"], "")
	if err != nil {
		return nil, err
	}

	zoneInfo, err := getStringFieldByPath(u, mapping["ZoneInfo"], "")
	if err != nil {
		return nil, err
	}

	locale, err := getStringFieldByPath(u, mapping["Locale"], "")
	if err != nil {
		return nil, err
	}

	updatedAt, err := getStringFieldByPath(u, mapping["UpdatedAt"], "")
	if err != nil {
		return nil, err
	}

	phone, err := getStringFieldByPath(u, mapping["Phone"], "")
	if err != nil {
		return nil, err
	}

	phoneVerified, err := getBooleanFieldByPath(u, mapping["PhoneVerified"], phone != "")
	if err != nil {
		return nil, err
	}

	data := &UserProvidedData{
		Emails: []Email{
			{
				Email:    email,
				Verified: emailVerified,
				Primary:  emailPrimary,
			},
		},
		Metadata: &Claims{
			Issuer:            issuer,
			Subject:           subject,
			Name:              name,
			FamilyName:        familyName,
			GivenName:         givenName,
			MiddleName:        middleName,
			NickName:          nickName,
			PreferredUsername: preferredUsername,
			Profile:           profile,
			Picture:           picture,
			Website:           website,
			Gender:            gender,
			Birthdate:         birthdate,
			ZoneInfo:          zoneInfo,
			Locale:            locale,
			UpdatedAt:         updatedAt,
			Email:             email,
			EmailVerified:     emailVerified,
			Phone:             phone,
			PhoneVerified:     phoneVerified,
		},
	}

	return data, nil
}

func getFieldByPath(obj map[string]interface{}, path string, fallback interface{}) (interface{}, error) {
	value := obj

	pathParts := strings.Split(path, ".")
	for index, field := range pathParts {
		fieldValue, ok := value[field]
		if !ok {
			return fallback, nil
		}

		if index == len(pathParts)-1 {
			return fieldValue, nil
		}

		value = fieldValue.(map[string]interface{})
	}

	return nil, nil
}

func getStringFieldByPath(obj map[string]interface{}, path string, fallback string) (string, error) {
	value, err := getFieldByPath(obj, path, fallback)
	if err != nil {
		return "", err
	}
	if result, ok := value.(string); ok {
		return result, nil
	} else if intValue, ok := value.(int); ok {
		return strconv.Itoa(intValue), nil
	} else if floatValue, ok := value.(float64); ok {
		return strconv.Itoa(int(math.Round(floatValue))), nil
	} else if value == nil {
		return "", nil
	} else {
		return "", fmt.Errorf("unable to read field as string: %q %q", path, value)
	}
}

func getBooleanFieldByPath(obj map[string]interface{}, path string, fallback bool) (bool, error) {
	value, err := getFieldByPath(obj, path, fallback)
	if err != nil {
		return false, err
	}
	if result, ok := value.(bool); ok {
		return result, nil
	} else {
		return false, fmt.Errorf("unable to read field as boolean: %q", path)
	}
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
		Issuer:          ext.Issuer,
		UserInfoURL:     ext.UserInfoURL,
		UserDataMapping: ext.UserDataMapping,
	}, nil
}
