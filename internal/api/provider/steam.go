package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/supabase/auth/internal/conf"
)

const (
	defaultSteamAuthBase = "steamcommunity.com"
	steamOpenIDEndpoint  = "https://steamcommunity.com/openid/login"
)

type steamProvider struct {
	Realm     string
	APIPath   string
}

var steamIDRegex = regexp.MustCompile(`^https?:\/\/steamcommunity\.com\/openid\/id\/(\d+)\/?$`)

// NewSteamProvider creates a Steam account provider.
func NewSteamProvider(ext conf.OAuthProviderConfiguration) (Provider, error) {
	if ext.Realm == "" {
		return nil, errors.New("No realm specified for Steam provider")
	}

	return &steamProvider{
		Realm:   ext.Realm,
		APIPath: chooseHost(ext.URL, defaultSteamAuthBase),
	}, nil
}

func (p steamProvider) GetAuthorizationURL(state string) string {
	params := url.Values{}
	params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select") 
	params.Add("openid.mode", "checkid_setup")
	params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Add("openid.realm", p.Realm)
	params.Add("openid.return_to", fmt.Sprintf("%s?state=%s", p.Realm, state))

	return steamOpenIDEndpoint + "?" + params.Encode()
}

func (p steamProvider) ValidateCallback(ctx context.Context, r *http.Request) (*UserProvidedData, error) {
	if mode := r.FormValue("openid.mode"); mode != "id_res" {
		return nil, fmt.Errorf("Invalid openid.mode: %s", mode)
	}

	// Verify signature
	params := url.Values{}
	params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Add("openid.mode", "check_authentication")

	// Copy all openid.* parameters
	for key, values := range r.URL.Query() {
		if strings.HasPrefix(key, "openid.") {
			params[key] = values
		}
	}

	// Verify with Steam
	resp, err := http.PostForm(steamOpenIDEndpoint, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(string(body), "is_valid:true") {
		return nil, errors.New("Invalid Steam authentication response")
	}

	// Extract Steam ID
	matches := steamIDRegex.FindStringSubmatch(r.FormValue("openid.claimed_id"))
	if len(matches) != 2 {
		return nil, errors.New("Invalid Steam ID format")
	}

	steamID := matches[1]

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:     steamOpenIDEndpoint,
			Subject:    steamID,
			ProviderId: steamID,
		},
	}

	return data, nil
} 