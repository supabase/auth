package api

// MCP authorization conformance for the OAuth 2.1 server.
//
// MCP clients (Claude, ChatGPT, Cursor, Claude Code, ...) sign users in to an MCP
// server through its authorization server. When a project uses Supabase Auth as
// that authorization server, these are the requirements the MCP authorization
// specification places on it. Each test drives the full router the way an MCP
// client does: discovery, registration, authorize, consent, token and refresh.
//
// Specification references:
//   - MCP 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
//   - MCP 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
//
// A requirement with a `pending` reference is a known gap. Its test is skipped
// while the gap exists, and fails once the behaviour is supported, so that the
// marker is removed in the same change that closes the gap.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	mcpResource      = "https://mcp.example.com/mcp"
	mcpOtherResource = "https://other.example.com/mcp"
	mcpConsentPath   = "/oauth/consent"
	mcpRedirectURI   = "https://client.example.com/callback"
	mcpLoopbackURI   = "http://127.0.0.1/callback"
	mcpUserEmail     = "mcp-conformance@example.com"
	mcpUserPassword  = "mcp-conformance-password"
)

type mcpRequirement struct {
	id      string
	title   string
	level   string // MUST or SHOULD, as written in the specification
	spec    string
	pending string // known gap: the issue, and the pull request proposing a fix
	check   func(t *testing.T, h *mcpHarness) error
}

var mcpRequirements = []mcpRequirement{
	{
		id: "AS-01", title: "authorization server metadata is published", level: "MUST",
		spec: "MCP 2025-11-25 Authorization §Overview (5); RFC 8414 §2",
		check: func(t *testing.T, h *mcpHarness) error {
			m := h.metadata(t)
			for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint"} {
				if s, _ := m[k].(string); s == "" {
					return fmt.Errorf("metadata has no %q", k)
				}
			}
			if !mcpContains(m["response_types_supported"], "code") {
				return fmt.Errorf("response_types_supported does not include code: %v", m["response_types_supported"])
			}
			for _, g := range []string{"authorization_code", "refresh_token"} {
				if !mcpContains(m["grant_types_supported"], g) {
					return fmt.Errorf("grant_types_supported does not include %s: %v", g, m["grant_types_supported"])
				}
			}
			return nil
		},
	},
	{
		id: "AS-02", title: "metadata advertises S256 PKCE", level: "MUST",
		spec: "MCP 2025-11-25 Security §Authorization Code Protection: clients MUST refuse to proceed when code_challenge_methods_supported is absent",
		check: func(t *testing.T, h *mcpHarness) error {
			m := h.metadata(t)
			if !mcpContains(m["code_challenge_methods_supported"], "S256") {
				return fmt.Errorf("code_challenge_methods_supported does not include S256: %v", m["code_challenge_methods_supported"])
			}
			return nil
		},
	},
	{
		id: "AS-03", title: "a public client can register dynamically", level: "MAY",
		spec: "MCP 2025-11-25 Client Registration §Dynamic Client Registration; RFC 7591 §3",
		check: func(t *testing.T, h *mcpHarness) error {
			m := h.metadata(t)
			if s, _ := m["registration_endpoint"].(string); s == "" {
				return fmt.Errorf("metadata has no registration_endpoint while dynamic registration is enabled")
			}
			w, body := h.register(t, mcpRedirectURI)
			if w.Code != http.StatusCreated && w.Code != http.StatusOK {
				return fmt.Errorf("registration returned %d: %s", w.Code, w.Body.String())
			}
			if s, _ := body["client_id"].(string); s == "" {
				return fmt.Errorf("registration response has no client_id")
			}
			return nil
		},
	},
	{
		id: "AS-04", title: "registration refuses an http redirect URI that is not loopback", level: "MUST",
		spec: "MCP 2025-11-25 Security §Communication Security: all redirect URIs MUST be either localhost or use HTTPS",
		check: func(t *testing.T, h *mcpHarness) error {
			w, _ := h.register(t, "http://client.example.com/callback")
			if w.Code < 400 || w.Code >= 500 {
				return fmt.Errorf("registration returned %d, want a 4xx refusal", w.Code)
			}
			return nil
		},
	},
	{
		id: "AS-05", title: "metadata advertises Client ID Metadata Documents", level: "SHOULD",
		spec:    "MCP 2025-11-25 Client Registration §Client ID Metadata Documents",
		pending: "supabase/auth#2850, fix proposed in #2895",
		check: func(t *testing.T, h *mcpHarness) error {
			m := h.metadata(t)
			if v, _ := m["client_id_metadata_document_supported"].(bool); !v {
				return fmt.Errorf("client_id_metadata_document_supported is %v", m["client_id_metadata_document_supported"])
			}
			return nil
		},
	},
	{
		id: "AS-06", title: "authorize without PKCE issues no code", level: "MUST",
		spec: "MCP 2025-11-25 §Overview (1): OAuth 2.1; OAuth 2.1 §4.1.1, §7.5.2",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			w := h.authorize(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", omitPKCE: true})
			loc, err := url.Parse(w.Header().Get("Location"))
			if w.Code != http.StatusFound || err != nil {
				return fmt.Errorf("authorize returned %d, want a redirect carrying an error", w.Code)
			}
			if strings.HasPrefix(loc.String(), h.consentURL()) {
				return fmt.Errorf("authorize sent the user to consent without PKCE")
			}
			if loc.Query().Get("error") != "invalid_request" || loc.Query().Has("code") {
				return fmt.Errorf("redirect was %s, want error=invalid_request and no code", loc)
			}
			return nil
		},
	},
	{
		id: "AS-07", title: "token exchange checks the PKCE verifier", level: "MUST",
		spec: "OAuth 2.1 §4.1.3; MCP 2025-11-25 Security §Authorization Code Protection",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			_, challenge := mcpPKCE()
			code, _ := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", challenge: challenge})
			wrong, _ := mcpPKCE()
			w, body := h.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {mcpRedirectURI}, "client_id": {client}, "code_verifier": {wrong}})
			if w.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
				return fmt.Errorf("a wrong code_verifier got %d %v, want 400 invalid_grant", w.Code, body["error"])
			}
			return nil
		},
	},
	{
		id: "AS-08", title: "an unregistered redirect URI is refused without redirecting", level: "MUST",
		spec: "MCP 2025-11-25 Security §Open Redirection: exact redirect URI match, no redirect to untrusted URIs",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			_, challenge := mcpPKCE()
			for _, uri := range []string{"https://attacker.example.com/callback", mcpRedirectURI + "/extra", mcpRedirectURI + "?x=1"} {
				w := h.authorize(t, mcpAuthorizeRequest{clientID: client, redirectURI: uri, state: "s", challenge: challenge})
				if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
					return fmt.Errorf("redirect_uri %s got %d with Location %q, want 400 and no redirect", uri, w.Code, w.Header().Get("Location"))
				}
			}
			return nil
		},
	},
	{
		id: "AS-09", title: "a loopback redirect URI may use any port", level: "MUST",
		spec:    "MCP 2025-11-25 §Overview (1): OAuth 2.1 §2.3.1 loopback exception; RFC 8252 §7.3",
		pending: "supabase/auth#2703, fix proposed in #2871",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpLoopbackURI)
			verifier, challenge := mcpPKCE()
			redirect := "http://127.0.0.1:49152/callback"
			w := h.authorize(t, mcpAuthorizeRequest{clientID: client, redirectURI: redirect, state: "s", challenge: challenge})
			if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), h.consentURL()) {
				return fmt.Errorf("loopback redirect on port 49152 got %d: %s", w.Code, w.Body.String())
			}
			loc := h.approve(t, w)
			if !strings.HasPrefix(loc.String(), redirect) {
				return fmt.Errorf("consent redirected to %s, want %s", loc, redirect)
			}
			tw, _ := h.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect}, "client_id": {client}, "code_verifier": {verifier}})
			if tw.Code != http.StatusOK {
				return fmt.Errorf("token exchange for the loopback redirect got %d: %s", tw.Code, tw.Body.String())
			}
			return nil
		},
	},
	{
		id: "AS-10", title: "the authorization response returns code and state exactly once", level: "MUST",
		spec: "OAuth 2.1 §4.1.2",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			_, challenge := mcpPKCE()
			state := "state-" + uuid.Must(uuid.NewV4()).String()
			_, loc := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: state, challenge: challenge})
			q := loc.Query()
			if len(q["code"]) != 1 || q.Get("code") == "" {
				return fmt.Errorf("authorization response code values: %v", q["code"])
			}
			if len(q["state"]) != 1 || q.Get("state") != state {
				return fmt.Errorf("authorization response state values %v, want [%s]", q["state"], state)
			}
			if q.Has("error") {
				return fmt.Errorf("authorization response carries error=%s", q.Get("error"))
			}
			return nil
		},
	},
	{
		id: "AS-11", title: "the token response is a no-store JSON bearer token", level: "MUST",
		spec: "OAuth 2.1 §3.2.3",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			w, body := h.fullFlow(t, client, mcpRedirectURI, "")
			if w.Code != http.StatusOK {
				return fmt.Errorf("token endpoint returned %d: %s", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				return fmt.Errorf("Content-Type is %q", ct)
			}
			if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
				return fmt.Errorf("Cache-Control is %q, want no-store", cc)
			}
			if s, _ := body["access_token"].(string); s == "" {
				return fmt.Errorf("no access_token")
			}
			if tt, _ := body["token_type"].(string); !strings.EqualFold(tt, "bearer") {
				return fmt.Errorf("token_type is %q", tt)
			}
			if s, _ := body["refresh_token"].(string); s == "" {
				return fmt.Errorf("no refresh_token for a client registered with the refresh_token grant")
			}
			return nil
		},
	},
	{
		id: "AS-12", title: "an authorization code can be redeemed only once", level: "MUST",
		spec: "OAuth 2.1 §4.1.3",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			verifier, challenge := mcpPKCE()
			code, _ := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", challenge: challenge})
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {mcpRedirectURI}, "client_id": {client}, "code_verifier": {verifier}}
			first, _ := h.token(t, form)
			require.Equal(t, http.StatusOK, first.Code, first.Body.String())
			second, body := h.token(t, form)
			if second.Code != http.StatusBadRequest || body["error"] != "invalid_grant" {
				return fmt.Errorf("a second redemption got %d %v, want 400 invalid_grant", second.Code, body["error"])
			}
			return nil
		},
	},
	{
		id: "AS-13", title: "the access token's audience includes the requested resource", level: "MUST",
		spec:    "MCP 2025-11-25 §Resource Parameter Implementation and §Token Handling: MCP servers MUST reject tokens whose audience is not them; RFC 8707 §2",
		pending: "supabase/auth#2610, fix proposed in #2894",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			w, body := h.fullFlow(t, client, mcpRedirectURI, mcpResource)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			aud, err := mcpAudience(body["access_token"])
			require.NoError(t, err)
			if !mcpContains(aud, mcpResource) {
				return fmt.Errorf("aud is %v, want it to include %s", aud, mcpResource)
			}
			return nil
		},
	},
	{
		id: "AS-14", title: "a token request for a different resource is refused with invalid_target", level: "MUST",
		spec:    "RFC 8707 §2; MCP clients send resource in token requests as form parameters",
		pending: "supabase/auth#2610, fix proposed in #2894",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			verifier, challenge := mcpPKCE()
			code, _ := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", challenge: challenge, resource: mcpResource})
			w, body := h.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {mcpRedirectURI}, "client_id": {client}, "code_verifier": {verifier}, "resource": {mcpOtherResource}})
			if w.Code != http.StatusBadRequest || body["error"] != "invalid_target" {
				return fmt.Errorf("a token request for %s got %d %v, want 400 invalid_target", mcpOtherResource, w.Code, body["error"])
			}
			return nil
		},
	},
	{
		id: "AS-15", title: "refresh tokens of public clients are rotated", level: "MUST",
		spec: "MCP 2025-11-25 Security §Token Theft: for public clients, authorization servers MUST rotate refresh tokens; OAuth 2.1 §4.3.1",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			w, body := h.fullFlow(t, client, mcpRedirectURI, "")
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			first, _ := body["refresh_token"].(string)
			refresh := func(rt string) (*httptest.ResponseRecorder, string) {
				rw, rbody := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}})
				next, _ := rbody["refresh_token"].(string)
				return rw, next
			}
			rw, second := refresh(first)
			if rw.Code != http.StatusOK || second == "" || second == first {
				return fmt.Errorf("refresh got %d and did not issue a new refresh token", rw.Code)
			}
			rw, third := refresh(second)
			if rw.Code != http.StatusOK || third == "" || third == second {
				return fmt.Errorf("second refresh got %d and did not issue a new refresh token", rw.Code)
			}
			// The immediate parent may be replayed by a client that failed to store
			// the response, and gets the already issued token back. Anything older
			// is a stolen token in use, and must be refused.
			if rw, _ := refresh(first); rw.Code == http.StatusOK {
				return fmt.Errorf("a refresh token two rotations old was accepted")
			}
			return nil
		},
	},
	{
		id: "AS-16", title: "a refreshed access token keeps the resource audience", level: "MUST",
		spec:    "RFC 8707 §2.2; MCP 2025-11-25 §Token Handling",
		pending: "supabase/auth#2610, fix proposed in #2894",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			w, body := h.fullFlow(t, client, mcpRedirectURI, mcpResource)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			rw, rbody := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {client}, "resource": {mcpResource}})
			if rw.Code != http.StatusOK {
				return fmt.Errorf("refresh with the granted resource returned %d: %s", rw.Code, rw.Body.String())
			}
			aud, err := mcpAudience(rbody["access_token"])
			require.NoError(t, err)
			if !mcpContains(aud, mcpResource) {
				return fmt.Errorf("refreshed aud is %v, want it to include %s", aud, mcpResource)
			}
			return nil
		},
	},
	{
		id: "AS-17", title: "the consent screen can show the redirect URI", level: "MUST",
		spec: "MCP 2025-11-25 Security §Localhost Redirect URI Risks: authorization servers MUST clearly display the redirect URI hostname",
		check: func(t *testing.T, h *mcpHarness) error {
			client := h.newPublicClient(t, mcpRedirectURI)
			_, challenge := mcpPKCE()
			w := h.authorize(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", challenge: challenge})
			details := h.authorizationDetails(t, w)
			if details["redirect_uri"] != mcpRedirectURI {
				return fmt.Errorf("authorization details redirect_uri is %v", details["redirect_uri"])
			}
			return nil
		},
	},
	{
		id: "AS-18", title: "the authorization response carries iss, and metadata says so", level: "SHOULD",
		spec:    "MCP 2026-07-28 Authorization §Authorization Response Validation; RFC 9207 §2",
		pending: "not yet filed",
		check: func(t *testing.T, h *mcpHarness) error {
			m := h.metadata(t)
			if v, _ := m["authorization_response_iss_parameter_supported"].(bool); !v {
				return fmt.Errorf("authorization_response_iss_parameter_supported is %v", m["authorization_response_iss_parameter_supported"])
			}
			client := h.newPublicClient(t, mcpRedirectURI)
			_, challenge := mcpPKCE()
			_, loc := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: mcpRedirectURI, state: "s", challenge: challenge})
			if loc.Query().Get("iss") != m["issuer"] {
				return fmt.Errorf("iss is %q, want the metadata issuer %v", loc.Query().Get("iss"), m["issuer"])
			}
			return nil
		},
	},
}

func TestMCPAuthorizationConformance(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
		if c == nil {
			return
		}
		c.OAuthServer.Enabled = true
		c.OAuthServer.AllowDynamicRegistration = true
		c.OAuthServer.AuthorizationPath = mcpConsentPath
		c.JWT.Issuer = "https://auth.example.com/auth/v1"
		// Rotation is observable only once the reuse window is closed.
		c.Security.RefreshTokenRotationEnabled = true
		c.Security.RefreshTokenReuseInterval = 0
	})
	require.NoError(t, err)
	defer api.db.Close()
	require.NoError(t, models.TruncateAll(api.db))

	h := &mcpHarness{api: api, config: config}
	h.signIn(t)

	for _, r := range mcpRequirements {
		r := r
		t.Run(r.id+" "+r.title, func(t *testing.T) {
			err := r.check(t, h)
			switch {
			case r.pending == "" && err != nil:
				t.Fatalf("%s (%s): %v", r.level, r.spec, err)
			case r.pending != "" && err == nil:
				t.Fatalf("now conforms; remove the pending marker (%s)", r.pending)
			case r.pending != "":
				t.Skipf("known gap, %s: %v", r.pending, err)
			}
		})
	}
}

type mcpHarness struct {
	api       *API
	config    *conf.GlobalConfiguration
	userToken string
}

type mcpAuthorizeRequest struct {
	clientID, redirectURI, state, challenge, resource string
	omitPKCE                                          bool
}

func (h *mcpHarness) do(t *testing.T, method, path string, body io.Reader, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	for k, v := range header {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.api.handler.ServeHTTP(w, req)
	return w
}

func (h *mcpHarness) signIn(t *testing.T) {
	u, err := models.NewUser("", mcpUserEmail, mcpUserPassword, h.config.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, h.api.db.Create(u))
	require.NoError(t, u.Confirm(h.api.db))

	body, _ := json.Marshal(map[string]string{"email": mcpUserEmail, "password": mcpUserPassword})
	w := h.do(t, http.MethodPost, "/token?grant_type=password", bytes.NewReader(body), http.Header{"Content-Type": {"application/json"}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tok map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&tok))
	h.userToken = tok["access_token"].(string)
}

func (h *mcpHarness) metadata(t *testing.T) map[string]any {
	w := h.do(t, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var m map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&m))
	return m
}

func (h *mcpHarness) register(t *testing.T, redirectURI string) (*httptest.ResponseRecorder, map[string]any) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "MCP conformance",
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
	w := h.do(t, http.MethodPost, "/oauth/clients/register", bytes.NewReader(body), http.Header{"Content-Type": {"application/json"}})
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

// newPublicClient stores a public client directly, so that most requirements do
// not depend on dynamic registration or its rate limit.
func (h *mcpHarness) newPublicClient(t *testing.T, redirectURIs ...string) string {
	c := &models.OAuthServerClient{
		ID:                      uuid.Must(uuid.NewV4()),
		RegistrationType:        "dynamic",
		ClientType:              models.OAuthServerClientTypePublic,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            strings.Join(redirectURIs, ","),
		GrantTypes:              "authorization_code,refresh_token",
	}
	require.NoError(t, models.CreateOAuthServerClient(h.api.db, c))
	return c.ID.String()
}

func (h *mcpHarness) consentURL() string {
	return strings.TrimSuffix(h.config.SiteURL, "/") + mcpConsentPath
}

func (h *mcpHarness) authorize(t *testing.T, r mcpAuthorizeRequest) *httptest.ResponseRecorder {
	q := url.Values{"response_type": {"code"}, "client_id": {r.clientID}, "redirect_uri": {r.redirectURI}, "state": {r.state}}
	if !r.omitPKCE {
		q.Set("code_challenge", r.challenge)
		q.Set("code_challenge_method", "S256")
	}
	if r.resource != "" {
		q.Set("resource", r.resource)
	}
	return h.do(t, http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, nil)
}

func (h *mcpHarness) authorizationID(t *testing.T, w *httptest.ResponseRecorder) string {
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(loc.String(), h.consentURL()), "authorize redirected to %s, not to consent", loc)
	id := loc.Query().Get("authorization_id")
	require.NotEmpty(t, id)
	return id
}

// authorizationDetails is what a consent page loads for the signed-in user.
func (h *mcpHarness) authorizationDetails(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	id := h.authorizationID(t, w)
	dw := h.do(t, http.MethodGet, "/oauth/authorizations/"+id, nil, http.Header{"Authorization": {"Bearer " + h.userToken}})
	require.Equal(t, http.StatusOK, dw.Code, dw.Body.String())
	var details map[string]any
	require.NoError(t, json.NewDecoder(dw.Body).Decode(&details))
	details["authorization_id"] = id
	return details
}

// approve plays the user on the consent page and returns the client's redirect.
func (h *mcpHarness) approve(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	details := h.authorizationDetails(t, w)
	redirect, _ := details["redirect_url"].(string) // consent given earlier is reused
	if redirect == "" {
		body, _ := json.Marshal(map[string]string{"action": "approve"})
		cw := h.do(t, http.MethodPost, "/oauth/authorizations/"+details["authorization_id"].(string)+"/consent", bytes.NewReader(body),
			http.Header{"Authorization": {"Bearer " + h.userToken}, "Content-Type": {"application/json"}})
		require.Equal(t, http.StatusOK, cw.Code, cw.Body.String())
		var resp map[string]any
		require.NoError(t, json.NewDecoder(cw.Body).Decode(&resp))
		redirect, _ = resp["redirect_url"].(string)
	}
	loc, err := url.Parse(redirect)
	require.NoError(t, err)
	return loc
}

func (h *mcpHarness) approvedCode(t *testing.T, r mcpAuthorizeRequest) (string, *url.URL) {
	loc := h.approve(t, h.authorize(t, r))
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "no code in %s", loc)
	return code, loc
}

// token posts form-encoded, as MCP clients do.
func (h *mcpHarness) token(t *testing.T, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	w := h.do(t, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func (h *mcpHarness) fullFlow(t *testing.T, client, redirectURI, resource string) (*httptest.ResponseRecorder, map[string]any) {
	verifier, challenge := mcpPKCE()
	code, _ := h.approvedCode(t, mcpAuthorizeRequest{clientID: client, redirectURI: redirectURI, state: "s", challenge: challenge, resource: resource})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "client_id": {client}, "code_verifier": {verifier}}
	if resource != "" {
		form.Set("resource", resource)
	}
	return h.token(t, form)
}

func mcpPKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// mcpAudience reads aud from a JWT without verifying it: the signature is not
// what these requirements are about.
func mcpAudience(token any) ([]string, error) {
	s, _ := token.(string)
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	return many, json.Unmarshal(claims.Aud, &many)
}

func mcpContains(list any, want string) bool {
	switch l := list.(type) {
	case []string:
		for _, v := range l {
			if v == want {
				return true
			}
		}
	case []any:
		for _, v := range l {
			if v == want {
				return true
			}
		}
	}
	return false
}
