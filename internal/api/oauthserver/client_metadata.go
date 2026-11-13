package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document)
// let a client use an HTTPS URL as its client_id. The URL serves the client's
// metadata, so the client does not need to register first.

const (
	// Recommended maximum document size from the specification
	clientMetadataMaxSize      = 5 * 1024
	clientMetadataFetchTimeout = 5 * time.Second

	// Bounds for caching documents, used together with Cache-Control
	clientMetadataDefaultTTL      = 5 * time.Minute
	clientMetadataMaxTTL          = 24 * time.Hour
	clientMetadataMaxCacheEntries = 1000
)

var ErrInvalidClientIDFormat = errors.New("invalid client_id format")

// clientMetadataError is returned when a Client ID Metadata Document can't be
// used. Reason is safe to return to the client.
type clientMetadataError struct {
	Reason   string
	Internal error
}

func (e *clientMetadataError) Error() string {
	if e.Internal != nil {
		return e.Reason + ": " + e.Internal.Error()
	}
	return e.Reason
}

func (e *clientMetadataError) Unwrap() error {
	return e.Internal
}

func newClientMetadataError(format string, args ...any) *clientMetadataError {
	return &clientMetadataError{Reason: fmt.Sprintf(format, args...)}
}

// FindClientByClientID returns the active client for a client_id sent in an
// OAuth request. The client_id is either a client UUID or, when enabled, a
// Client ID Metadata Document URL of a client that went through /authorize.
func FindClientByClientID(db *storage.Connection, config *conf.OAuthServerConfiguration, clientID string) (*models.OAuthServerClient, error) {
	if id, err := uuid.FromString(clientID); err == nil {
		return models.FindOAuthServerClientByID(db, id)
	}

	if config.AllowClientIDMetadataDocuments && strings.HasPrefix(clientID, "https://") {
		return models.FindOAuthServerClientByClientIDURL(db, clientID)
	}

	return nil, ErrInvalidClientIDFormat
}

// validateClientIDURL checks the Client Identifier URL rules from the specification
func validateClientIDURL(clientIDURL string, allowedHosts []string) error {
	if len(clientIDURL) > 2048 {
		return newClientMetadataError("client_id URL must be at most 2048 characters")
	}

	u, err := url.Parse(clientIDURL)
	if err != nil {
		return newClientMetadataError("client_id must be a valid URL")
	}

	if u.Scheme != "https" {
		return newClientMetadataError("client_id URL must use https")
	}

	if u.User != nil {
		return newClientMetadataError("client_id URL must not contain user info")
	}

	if u.Hostname() == "" {
		return newClientMetadataError("client_id URL must contain a host")
	}

	if u.Path == "" || u.Path == "/" {
		return newClientMetadataError("client_id URL must contain a path")
	}

	// u.Path is decoded, so percent-encoded dots are caught too
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return newClientMetadataError("client_id URL must not contain dot path segments")
		}
	}

	if u.Fragment != "" || strings.Contains(clientIDURL, "#") {
		return newClientMetadataError("client_id URL must not contain a fragment")
	}

	if u.RawQuery != "" || u.ForceQuery {
		return newClientMetadataError("client_id URL must not contain a query")
	}

	if len(allowedHosts) > 0 && !slices.ContainsFunc(allowedHosts, func(host string) bool {
		return strings.EqualFold(strings.TrimSpace(host), u.Hostname())
	}) {
		return newClientMetadataError("client_id URL host is not allowed")
	}

	return nil
}

// clientMetadataDocument holds the client metadata properties this server uses
type clientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`

	// Must not be present, only kept to detect them
	ClientSecret          json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt json.RawMessage `json:"client_secret_expires_at,omitempty"`
}

func (d *clientMetadataDocument) validate(clientIDURL string) error {
	// Simple string comparison, as required by the specification
	if d.ClientID != clientIDURL {
		return newClientMetadataError("client_id in the client metadata document does not match the client_id URL")
	}

	if len(d.ClientSecret) > 0 || len(d.ClientSecretExpiresAt) > 0 {
		return newClientMetadataError("client metadata document must not contain client_secret or client_secret_expires_at")
	}

	// Shared secrets can't be used with metadata documents, and this server
	// does not support private_key_jwt, so only public clients are possible
	if d.TokenEndpointAuthMethod != "" && d.TokenEndpointAuthMethod != models.TokenEndpointAuthMethodNone {
		return newClientMetadataError("token_endpoint_auth_method must be '%s'", models.TokenEndpointAuthMethodNone)
	}

	if err := validateRedirectURIList(d.RedirectURIs, true); err != nil {
		return newClientMetadataError("%s", validationMessage(err))
	}

	if len(d.GrantTypes) > 0 {
		if err := validateGrantTypeList(d.GrantTypes); err != nil {
			return newClientMetadataError("%s", validationMessage(err))
		}
	}

	if err := validateClientName(d.ClientName); err != nil {
		return newClientMetadataError("%s", validationMessage(err))
	}
	if err := validateClientURI(d.ClientURI); err != nil {
		return newClientMetadataError("%s", validationMessage(err))
	}
	if err := validateLogoURI(d.LogoURI); err != nil {
		return newClientMetadataError("%s", validationMessage(err))
	}

	return nil
}

// applyTo copies the document's metadata to the client and reports whether anything changed
func (d *clientMetadataDocument) applyTo(client *models.OAuthServerClient) bool {
	grantTypes := d.GrantTypes
	if len(grantTypes) == 0 {
		// Same default as dynamic client registration
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	before := []string{
		client.RedirectURIs,
		client.GrantTypes,
		utilities.StringValue(client.ClientName),
		utilities.StringValue(client.ClientURI),
		utilities.StringValue(client.LogoURI),
	}

	client.SetRedirectURIs(d.RedirectURIs)
	client.SetGrantTypes(grantTypes)
	client.ClientName = utilities.StringPtr(d.ClientName)
	client.ClientURI = utilities.StringPtr(d.ClientURI)
	client.LogoURI = utilities.StringPtr(d.LogoURI)

	after := []string{
		client.RedirectURIs,
		client.GrantTypes,
		utilities.StringValue(client.ClientName),
		utilities.StringValue(client.ClientURI),
		utilities.StringValue(client.LogoURI),
	}

	return !slices.Equal(before, after)
}

func validationMessage(err error) string {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Message
	}
	return err.Error()
}

type cachedClientMetadata struct {
	document  *clientMetadataDocument
	expiresAt time.Time
}

// clientMetadataFetcher fetches and caches Client ID Metadata Documents
type clientMetadataFetcher struct {
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]cachedClientMetadata
}

func newClientMetadataFetcher(client *http.Client) *clientMetadataFetcher {
	if client == nil {
		client = newClientMetadataHTTPClient()
	}

	// The specification forbids following redirects
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &clientMetadataFetcher{
		client: &noRedirects,
		now:    time.Now,
		cache:  make(map[string]cachedClientMetadata),
	}
}

// newClientMetadataHTTPClient returns a client that refuses to connect to
// special-use IP addresses (RFC 6890). The check runs on the address actually
// dialed, so DNS rebinding can't bypass it. Proxies are not used for the same
// reason.
func newClientMetadataHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: clientMetadataFetchTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if isSpecialUseAddr(addr) {
				return fmt.Errorf("refusing to connect to special-use address %s", addr)
			}
			return nil
		},
	}

	return &http.Client{
		Timeout: clientMetadataFetchTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   clientMetadataFetchTimeout,
			ResponseHeaderTimeout: clientMetadataFetchTimeout,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// Special-use ranges from RFC 6890 not covered by the netip.Addr methods,
// plus deprecated IPv6 ranges that netip treats as global unicast
var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("::/96"),     // IPv4-compatible addresses (deprecated, RFC 4291)
	netip.MustParsePrefix("fec0::/10"), // Site-local addresses (deprecated, RFC 3879)
}

func isSpecialUseAddr(addr netip.Addr) bool {
	addr = addr.Unmap()

	// Loopback, link-local, multicast, unspecified and private addresses
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}

	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// fetch returns the validated Client ID Metadata Document for the URL, from
// the cache when possible. Errors and invalid documents are never cached.
func (f *clientMetadataFetcher) fetch(ctx context.Context, clientIDURL string) (*clientMetadataDocument, error) {
	if document, ok := f.cached(clientIDURL); ok {
		return document, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return nil, &clientMetadataError{Reason: "unable to fetch client metadata document", Internal: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Supabase-Auth/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, &clientMetadataError{Reason: "unable to fetch client metadata document", Internal: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newClientMetadataError("client metadata document request returned HTTP status %d", resp.StatusCode)
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !isJSONMediaType(mediaType) {
		return nil, newClientMetadataError("client metadata document must be served as JSON")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, clientMetadataMaxSize+1))
	if err != nil {
		return nil, &clientMetadataError{Reason: "unable to read client metadata document", Internal: err}
	}
	if len(body) > clientMetadataMaxSize {
		return nil, newClientMetadataError("client metadata document must be at most %d bytes", clientMetadataMaxSize)
	}

	var document clientMetadataDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, newClientMetadataError("client metadata document is not valid JSON")
	}

	if err := document.validate(clientIDURL); err != nil {
		return nil, err
	}

	f.store(clientIDURL, &document, clientMetadataCacheTTL(resp.Header))

	return &document, nil
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

// clientMetadataCacheTTL derives how long to cache a document from its
// Cache-Control header, within this server's bounds
func clientMetadataCacheTTL(header http.Header) time.Duration {
	cacheControl := header.Get("Cache-Control")
	if cacheControl == "" {
		return clientMetadataDefaultTTL
	}

	for _, directive := range strings.Split(strings.ToLower(cacheControl), ",") {
		directive = strings.TrimSpace(directive)

		switch {
		case directive == "no-store" || directive == "no-cache":
			return 0

		case strings.HasPrefix(directive, "max-age="):
			seconds, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(directive, "max-age="), `"`))
			if err != nil || seconds <= 0 {
				return 0
			}
			return min(time.Duration(seconds)*time.Second, clientMetadataMaxTTL)
		}
	}

	return clientMetadataDefaultTTL
}

func (f *clientMetadataFetcher) cached(clientIDURL string) (*clientMetadataDocument, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry, ok := f.cache[clientIDURL]
	if !ok {
		return nil, false
	}
	if !f.now().Before(entry.expiresAt) {
		delete(f.cache, clientIDURL)
		return nil, false
	}
	return entry.document, true
}

func (f *clientMetadataFetcher) store(clientIDURL string, document *clientMetadataDocument, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if len(f.cache) >= clientMetadataMaxCacheEntries {
		for key, entry := range f.cache {
			if !now.Before(entry.expiresAt) {
				delete(f.cache, key)
			}
		}
		if len(f.cache) >= clientMetadataMaxCacheEntries {
			// Still full: skip caching rather than grow without bound
			return
		}
	}

	f.cache[clientIDURL] = cachedClientMetadata{document: document, expiresAt: now.Add(ttl)}
}

// resolveMetadataDocumentClient fetches the Client ID Metadata Document for
// the URL and returns the client for it, creating or updating the client so
// each URL maps to a single client.
func (s *Server) resolveMetadataDocumentClient(ctx context.Context, clientIDURL string) (*models.OAuthServerClient, error) {
	if err := validateClientIDURL(clientIDURL, s.config.OAuthServer.ClientIDMetadataDocumentAllowedHosts); err != nil {
		return nil, err
	}

	document, err := s.clientMetadata.fetch(ctx, clientIDURL)
	if err != nil {
		return nil, err
	}

	db := s.db.WithContext(ctx)

	client, err := models.FindOAuthServerClientByClientIDURL(db, clientIDURL)
	if err == nil {
		if document.applyTo(client) {
			if err := models.UpdateOAuthServerClient(db, client); err != nil {
				return nil, err
			}
		}
		return client, nil
	}
	if !models.IsNotFoundError(err) {
		return nil, err
	}

	client = &models.OAuthServerClient{
		ID:                      uuid.Must(uuid.NewV4()),
		RegistrationType:        models.OAuthServerRegistrationTypeMetadataDocument,
		ClientType:              models.OAuthServerClientTypePublic,
		TokenEndpointAuthMethod: models.TokenEndpointAuthMethodNone,
		ClientIDURL:             &clientIDURL,
	}
	document.applyTo(client)

	if err := models.CreateOAuthServerClient(db, client); err != nil {
		// A concurrent request may have created the client first
		if existing, findErr := models.FindOAuthServerClientByClientIDURL(db, clientIDURL); findErr == nil {
			return existing, nil
		}
		return nil, err
	}

	return client, nil
}
