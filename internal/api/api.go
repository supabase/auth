package api

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	"github.com/sebest/xff"
	"github.com/sirupsen/logrus"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/mailer"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/storage"
)

const (
	audHeaderName  = "X-JWT-AUD"
	defaultVersion = "unknown version"
)

var bearerRegexp = regexp.MustCompile(`^(?:B|b)earer (\S+$)`)

// API is the main REST API
type API struct {
	handler http.Handler
	db      *storage.Connection
	config  *conf.GlobalConfiguration
	version string
}

// NewAPI instantiates a new REST API
func NewAPI(globalConfig *conf.GlobalConfiguration, db *storage.Connection) *API {
	return NewAPIWithVersion(context.Background(), globalConfig, db, defaultVersion)
}

func (a *API) deprecationNotices(ctx context.Context) {
	config := a.config

	log := logrus.WithField("component", "api")

	if config.JWT.AdminGroupName != "" {
		log.Warn("DEPRECATION NOTICE: GOTRUE_JWT_ADMIN_GROUP_NAME not supported by Supabase's GoTrue, will be removed soon")
	}

	if config.JWT.DefaultGroupName != "" {
		log.Warn("DEPRECATION NOTICE: GOTRUE_JWT_DEFAULT_GROUP_NAME not supported by Supabase's GoTrue, will be removed soon")
	}
}

// NewAPIWithVersion creates a new REST API using the specified version
func NewAPIWithVersion(ctx context.Context, globalConfig *conf.GlobalConfiguration, db *storage.Connection, version string) *API {
	api := &API{config: globalConfig, db: db, version: version}

	api.deprecationNotices(ctx)

	xffmw, _ := xff.Default()
	logger := observability.NewStructuredLogger(logrus.StandardLogger())

	r := newRouter()
	r.Use(addRequestID(globalConfig))

	// request tracing should be added only when tracing or metrics is
	// enabled
	if globalConfig.Tracing.Enabled {
		switch globalConfig.Tracing.Exporter {
		case conf.OpenTracing:
			r.UseBypass(opentracer)

		default:
			r.UseBypass(observability.RequestTracing())
		}
	} else if globalConfig.Metrics.Enabled {
		r.UseBypass(observability.RequestTracing())
	}

	r.UseBypass(xffmw.Handler)
	r.Use(recoverer)

	r.Get("/health", api.HealthCheck)

	r.Route("/callback", func(r *router) {
		r.UseBypass(logger)
		r.Use(api.loadFlowState)

		r.Get("/", api.ExternalProviderCallback)
		r.Post("/", api.ExternalProviderCallback)
	})

	r.Route("/", func(r *router) {
		r.UseBypass(logger)

		r.Get("/settings", api.Settings)

		r.Get("/authorize", api.ExternalProviderRedirect)

		sharedLimiter := api.limitEmailOrPhoneSentHandler()
		r.With(sharedLimiter).With(api.requireAdminCredentials).Post("/invite", api.Invite)
		r.With(sharedLimiter).With(api.verifyCaptcha).Post("/signup", api.Signup)
		r.With(sharedLimiter).With(api.verifyCaptcha).With(api.requireEmailProvider).Post("/recover", api.Recover)
		r.With(sharedLimiter).With(api.verifyCaptcha).With(api.requireEmailProvider).Post("/resend", api.Resend)
		r.With(sharedLimiter).With(api.verifyCaptcha).Post("/magiclink", api.MagicLink)

		r.With(sharedLimiter).With(api.verifyCaptcha).Post("/otp", api.Otp)

		r.With(api.limitHandler(
			// Allow requests at the specified rate per 5 minutes.
			tollbooth.NewLimiter(api.config.RateLimitTokenRefresh/(60*5), &limiter.ExpirableOptions{
				DefaultExpirationTTL: time.Hour,
			}).SetBurst(30),
		)).With(api.verifyCaptcha).Post("/token", api.Token)

		r.With(api.limitHandler(
			// Allow requests at the specified rate per 5 minutes.
			tollbooth.NewLimiter(api.config.RateLimitVerify/(60*5), &limiter.ExpirableOptions{
				DefaultExpirationTTL: time.Hour,
			}).SetBurst(30),
		)).Route("/verify", func(r *router) {
			r.Get("/", api.Verify)
			r.Post("/", api.Verify)
		})

		r.With(api.requireAuthentication).Post("/logout", api.Logout)

		r.With(api.requireAuthentication).Route("/reauthenticate", func(r *router) {
			r.Get("/", api.Reauthenticate)
		})

		r.With(api.requireAuthentication).Route("/user", func(r *router) {
			r.Get("/", api.UserGet)
			r.With(sharedLimiter).Put("/", api.UserUpdate)
		})

		r.With(api.requireAuthentication).Route("/factors", func(r *router) {
			r.Post("/", api.EnrollFactor)
			r.Route("/{factor_id}", func(r *router) {
				r.Use(api.loadFactor)

				r.With(api.limitHandler(
					tollbooth.NewLimiter(api.config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
						DefaultExpirationTTL: time.Minute,
					}).SetBurst(30))).Post("/verify", api.VerifyFactor)
				r.With(api.limitHandler(
					tollbooth.NewLimiter(api.config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
						DefaultExpirationTTL: time.Minute,
					}).SetBurst(30))).Post("/challenge", api.ChallengeFactor)
				r.Delete("/", api.UnenrollFactor)

			})
		})

		r.Route("/sso", func(r *router) {
			r.Use(api.requireSAMLEnabled)
			r.With(api.limitHandler(
				// Allow requests at the specified rate per 5 minutes.
				tollbooth.NewLimiter(api.config.RateLimitSso/(60*5), &limiter.ExpirableOptions{
					DefaultExpirationTTL: time.Hour,
				}).SetBurst(30),
			)).With(api.verifyCaptcha).Post("/", api.SingleSignOn)

			r.Route("/saml", func(r *router) {
				r.Get("/metadata", api.SAMLMetadata)

				r.With(api.limitHandler(
					// Allow requests at the specified rate per 5 minutes.
					tollbooth.NewLimiter(api.config.SAML.RateLimitAssertion/(60*5), &limiter.ExpirableOptions{
						DefaultExpirationTTL: time.Hour,
					}).SetBurst(30),
				)).Post("/acs", api.SAMLACS)
			})
		})

		r.Route("/admin", func(r *router) {
			r.Use(api.requireAdminCredentials)

			r.Route("/audit", func(r *router) {
				r.Get("/", api.adminAuditLog)
			})

			r.Route("/users", func(r *router) {
				r.Get("/", api.adminUsers)
				r.Post("/", api.adminUserCreate)

				r.Route("/{user_id}", func(r *router) {
					r.Use(api.loadUser)
					r.Route("/factors", func(r *router) {
						r.Get("/", api.adminUserGetFactors)
						r.Route("/{factor_id}", func(r *router) {
							r.Use(api.loadFactor)
							r.Delete("/", api.adminUserDeleteFactor)
							r.Put("/", api.adminUserUpdateFactor)
						})
					})

					r.Get("/", api.adminUserGet)
					r.Put("/", api.adminUserUpdate)
					r.Delete("/", api.adminUserDelete)
				})
			})

			r.Post("/generate_link", api.GenerateLink)

			r.Route("/sso", func(r *router) {
				r.Route("/providers", func(r *router) {
					r.Get("/", api.adminSSOProvidersList)
					r.Post("/", api.adminSSOProvidersCreate)

					r.Route("/{idp_id}", func(r *router) {
						r.Use(api.loadSSOProvider)

						r.Get("/", api.adminSSOProvidersGet)
						r.Put("/", api.adminSSOProvidersUpdate)
						r.Delete("/", api.adminSSOProvidersDelete)
					})
				})
			})

		})
	})

	corsHandler := cors.New(cors.Options{
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Client-IP", "X-Client-Info", audHeaderName, useCookieHeader},
		ExposedHeaders:   []string{"X-Total-Count", "Link"},
		AllowCredentials: true,
	})

	api.handler = corsHandler.Handler(chi.ServerBaseContext(ctx, r))
	return api
}

type HealthCheckResponse struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// HealthCheck endpoint indicates if the gotrue api service is available
func (a *API) HealthCheck(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, HealthCheckResponse{
		Version:     a.version,
		Name:        "GoTrue",
		Description: "GoTrue is a user registration and authentication API",
	})
}

// Mailer returns NewMailer with the current tenant config
func (a *API) Mailer(ctx context.Context) mailer.Mailer {
	config := a.config
	return mailer.NewMailer(config)
}
