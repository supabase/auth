package api

import (
	"math"
	"net/http"
	"strconv"

	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase/auth/internal/api/scim"
)

func (a *API) limitSCIMByIP(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.performRateLimiting(lmt, r) != nil {
				if perSecond := lmt.GetMax(); perSecond > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(1/perSecond))))
				}
				_ = scim.SendTooManyRequests(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
