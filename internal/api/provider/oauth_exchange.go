package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// rawBasicAuthTransport rewrites Authorization: Basic to use the raw client
// id and secret. golang.org/x/oauth2 url.QueryEscape-s credentials for
// AuthStyleInHeader (RFC 6749 §2.3.1), which breaks providers that expect a
// raw secret (e.g. Epic Games). See https://github.com/supabase/auth/issues/2623
type rawBasicAuthTransport struct {
	base                   http.RoundTripper
	clientID, clientSecret string
}

func (t *rawBasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Header.Get("Authorization") != "" {
		req = req.Clone(req.Context())
		req.SetBasicAuth(t.clientID, t.clientSecret)
	}
	return base.RoundTrip(req)
}

// exchangeAuthorizationCode exchanges an auth code using HTTP Basic with the
// raw (unescaped) client secret. AuthStyle is forced to InHeader so oauth2
// does not auto-detect and retry as client_secret_post (which masks errors).
func exchangeAuthorizationCode(ctx context.Context, cfg *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	cfgCopy := *cfg
	cfgCopy.Endpoint.AuthStyle = oauth2.AuthStyleInHeader

	base := http.DefaultTransport
	timeout := defaultTimeout
	if existing, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && existing != nil {
		if existing.Timeout != 0 {
			timeout = existing.Timeout
		}
		if existing.Transport != nil {
			base = existing.Transport
		}
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &rawBasicAuthTransport{
			base:         base,
			clientID:     cfg.ClientID,
			clientSecret: cfg.ClientSecret,
		},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	return cfgCopy.Exchange(ctx, code, opts...)
}
