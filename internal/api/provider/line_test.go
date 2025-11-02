package provider

import (
	"testing"

	"github.com/supabase/auth/internal/conf"
)

func TestNewLineProvider_DefaultApiHostFallback(t *testing.T) {
	cfg := conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"client-id"},
		Secret:      "client-secret",
		RedirectURI: "https://example.com/callback",
		URL:         "https://access.line.me",
	}

	provider, err := NewLineProvider(cfg, "")
	if err != nil {
		t.Fatalf("NewLineProvider returned error: %v", err)
	}

	p, ok := provider.(*lineProvider)
	if !ok {
		t.Fatalf("expected *lineProvider, got %T", provider)
	}

	if expected := "https://api.line.me"; p.APIHost != expected {
		t.Fatalf("unexpected APIHost: got %q want %q", p.APIHost, expected)
	}

	if expected := "https://api.line.me/oauth2/v2.1/token"; p.Endpoint.TokenURL != expected {
		t.Fatalf("unexpected TokenURL: got %q want %q", p.Endpoint.TokenURL, expected)
	}

	if expected := "https://access.line.me/oauth2/v2.1/authorize"; p.Endpoint.AuthURL != expected {
		t.Fatalf("unexpected AuthURL: got %q want %q", p.Endpoint.AuthURL, expected)
	}
}
