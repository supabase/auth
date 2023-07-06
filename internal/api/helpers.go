package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/utilities"
)

func addRequestID(globalConfig *conf.GlobalConfiguration) middlewareHandler {
	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		id := ""
		if globalConfig.API.RequestIDHeader != "" {
			id = r.Header.Get(globalConfig.API.RequestIDHeader)
		}
		if id == "" {
			uid := uuid.Must(uuid.NewV4())
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

func isAdmin(u *models.User, config *conf.GlobalConfiguration) bool {
	return config.JWT.Aud == u.Aud && u.HasRole(config.JWT.AdminGroupName)
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

	// Finally, return the default if none of the above methods are successful
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
	for _, pattern := range config.URIAllowListMap {
		if pattern.Match(redirectURL) {
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
	return utilities.GetBodyBytes(req)
}
