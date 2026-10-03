package api

import (
	"context"
	"errors"
	"math"
	"net/http"
	"path"
	"strconv"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/server"
)

func (a *API) limitSCIMByIP(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.scimSkipsTokenValidator(r) && a.performRateLimiting(lmt, r) != nil {
				handler(scimTooManyRequests(lmt))(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) scimSkipsTokenValidator(r *http.Request) bool {
	if _, err := a.extractBearerToken(r); err != nil {
		return true
	}
	return r.URL.Path == scimBasePath+"/ServiceProviderConfig" || path.Clean(r.URL.Path) != r.URL.Path
}

func (a *API) limitSCIMInvalidToken(validate server.TokenValidator, lmt *limiter.Limiter) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		next, err := validate(ctx, candidate)
		if !errors.Is(err, server.ErrInvalidToken) {
			return next, err
		}
		if r := scimRequestKey.Value(ctx); r != nil && a.performRateLimiting(lmt, r) != nil {
			return ctx, errSCIMTooManyRequests()
		}
		return next, err
	}
}

func (a *API) limitSCIMByProvider(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if providerID, err := scimProviderID(r.Context()); err == nil && tollbooth.LimitByKeys(lmt, []string{providerID.String()}) != nil {
				handler(scimTooManyRequests(lmt))(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func scimTooManyRequests(lmt *limiter.Limiter) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if perSecond := lmt.GetMax(); perSecond > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(1/perSecond))))
		}
		return protocol.SendError(w, errSCIMTooManyRequests())
	}
}
