package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func addRequestID(globalConfig *conf.GlobalConfiguration) middlewareHandler {
	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		id := ""
		if globalConfig.API.RequestIDHeader != "" {
			id = r.Header.Get(globalConfig.API.RequestIDHeader)
		}
		if id == "" {
			uid, err := uuid.NewV4()
			if err != nil {
				return nil, err
			}
			id = uid.String()
		}

		ctx := r.Context()
		ctx = withRequestID(ctx, id)
		return ctx, nil
	}
}

func sendJSON(w http.ResponseWriter, status int, obj interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(obj)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error encoding json response: %v", obj))
	}
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}

func (a *API) isAdmin(ctx context.Context, u *models.User, aud string) bool {
	config := a.config
	if aud == "" {
		aud = config.JWT.Aud
	}
	return aud == u.Aud && u.HasRole(config.JWT.AdminGroupName)
}

func (a *API) requestAud(ctx context.Context, r *http.Request) string {
	config := a.config
	// First check for an audience in the header
	if aud := r.Header.Get(audHeaderName); aud != "" {
		return aud
	}

	// Then check the token
	claims := getClaims(ctx)
	if claims != nil && claims.Audience != "" {
		return claims.Audience
	}

	// Finally, return the default of none of the above methods are successful
	return config.JWT.Aud
}

// tries extract redirect url from header or from query params
func getRedirectTo(r *http.Request) (reqref string) {
	reqref = r.Header.Get("redirect_to")
	if reqref != "" {
		return
	}

	if err := r.ParseForm(); err == nil {
		reqref = r.Form.Get("redirect_to")
	}

	return
}

func isRedirectURLValid(config *conf.GlobalConfiguration, redirectURL string) bool {
	if redirectURL == "" {
		return false
	}

	base, berr := url.Parse(config.SiteURL)
	refurl, rerr := url.Parse(redirectURL)

	// As long as the referrer came from the site, we will redirect back there
	if berr == nil && rerr == nil && base.Hostname() == refurl.Hostname() {
		return true
	}

	// For case when user came from mobile app or other permitted resource - redirect back
	for uri, g := range config.URIAllowListMap {
		// Only allow wildcard matching if url scheme is http(s)
		if strings.HasPrefix(uri, "http") || strings.HasPrefix(uri, "https") {
			if g.Match(redirectURL) {
				return true
			}
		} else if redirectURL == uri {
			return true
		}
	}

	return false
}

func (a *API) getReferrer(r *http.Request) string {
	config := a.config

	// try get redirect url from query or post data first
	reqref := getRedirectTo(r)
	if isRedirectURLValid(config, reqref) {
		return reqref
	}

	// instead try referrer header value
	reqref = r.Referer()
	if isRedirectURLValid(config, reqref) {
		return reqref
	}

	return config.SiteURL
}

// getRedirectURLOrReferrer ensures any redirect URL is from a safe origin
func (a *API) getRedirectURLOrReferrer(r *http.Request, reqref string) string {
	config := a.config

	// if redirect url fails - try fill by extra variant
	if isRedirectURLValid(config, reqref) {
		return reqref
	}

	return a.getReferrer(r)
}

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"100.64.0.0/10",  // RFC6598
		"172.16.0.0/12",  // RFC1918
		"192.0.0.0/24",   // RFC6890
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

type noLocalTransport struct {
	inner  http.RoundTripper
	errlog logrus.FieldLogger
}

func (no noLocalTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())

	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			fmt.Printf("Checking network %v\n", addr)
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				cancel()
				fmt.Printf("Canceleing dur to error in addr parsing %v", err)
				return
			}
			ip := net.ParseIP(host)
			if ip == nil {
				cancel()
				fmt.Printf("Canceleing dur to error in ip parsing %v", host)
				return
			}

			if isPrivateIP(ip) {
				cancel()
				fmt.Println("Canceleing dur to private ip range")
				return
			}

		},
	})

	req = req.WithContext(ctx)
	return no.inner.RoundTrip(req)
}

func SafeRoundtripper(trans http.RoundTripper, log logrus.FieldLogger) http.RoundTripper {
	if trans == nil {
		trans = http.DefaultTransport
	}

	ret := &noLocalTransport{
		inner:  trans,
		errlog: log.WithField("transport", "local_blocker"),
	}

	return ret
}

func SafeHTTPClient(client *http.Client, log logrus.FieldLogger) *http.Client {
	client.Transport = SafeRoundtripper(client.Transport, log)

	return client
}

func isStringInSlice(checkValue string, list []string) bool {
	for _, val := range list {
		if val == checkValue {
			return true
		}
	}
	return false
}

// getBodyBytes returns a byte array of the request's Body.
func getBodyBytes(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	originalBody := req.Body
	defer originalBody.Close()

	buf, err := io.ReadAll(originalBody)
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewReader(buf))

	return buf, nil
}
