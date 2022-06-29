package api

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/imdario/mergo"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/mailer"
	"github.com/netlify/gotrue/storage"
	"github.com/rs/cors"
	"github.com/sebest/xff"
	"github.com/sirupsen/logrus"
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

// ListenAndServe starts the REST API
func (a *API) ListenAndServe(hostAndPort string) {
	log := logrus.WithField("component", "api")
	server := &http.Server{
		Addr:    hostAndPort,
		Handler: a.handler,
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		waitForTermination(log, done)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.WithError(err).Fatal("http server listen failed")
	}
}

// WaitForShutdown blocks until the system signals termination or done has a value
func waitForTermination(log logrus.FieldLogger, done <-chan struct{}) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	select {
	case sig := <-signals:
		log.Infof("Triggering shutdown from signal %s", sig)
	case <-done:
		log.Infof("Shutting down...")
	}
}

// NewAPI instantiates a new REST API
func NewAPI(globalConfig *conf.GlobalConfiguration, db *storage.Connection) *API {
	return NewAPIWithVersion(context.Background(), globalConfig, db, defaultVersion)
}

// NewAPIWithVersion creates a new REST API using the specified version
func NewAPIWithVersion(ctx context.Context, globalConfig *conf.GlobalConfiguration, db *storage.Connection, version string) *API {
	api := &API{config: globalConfig, db: db, version: version}

	xffmw, _ := xff.Default()
	logger := newStructuredLogger(logrus.StandardLogger())

	r := newRouter()
	r.UseBypass(xffmw.Handler)
	r.Use(addRequestID(globalConfig))
	r.Use(recoverer)
	r.UseBypass(tracer)

	r.Get("/health", api.HealthCheck)

	r.Route("/callback", func(r *router) {
		r.UseBypass(logger)
		r.Use(api.loadOAuthState)

		if globalConfig.MultiInstanceMode {
			r.Use(api.loadInstanceConfig)
		}
		r.Get("/", api.ExternalProviderCallback)
		r.Post("/", api.ExternalProviderCallback)
	})

	r.Route("/", func(r *router) {
		r.UseBypass(logger)

		if globalConfig.MultiInstanceMode {
			r.Use(api.loadJWSSignatureHeader)
			r.Use(api.loadInstanceConfig)
		}

		r.Get("/settings", api.Settings)

		r.Get("/authorize", api.ExternalProviderRedirect)

		sharedLimiter := api.limitEmailSentHandler()
		r.With(sharedLimiter).With(api.requireAdminCredentials).Post("/invite", api.Invite)
		r.With(sharedLimiter).With(api.verifyCaptcha).Post("/signup", api.Signup)
		r.With(sharedLimiter).With(api.verifyCaptcha).With(api.requireEmailProvider).Post("/recover", api.Recover)
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
			r.With(api.verifyCaptcha).Post("/", api.Verify)
		})

		r.With(api.requireAuthentication).Post("/logout", api.Logout)

		r.Route("/reauthenticate", func(r *router) {
			r.Use(api.requireAuthentication)
			r.Get("/", api.Reauthenticate)
		})

		r.Route("/user", func(r *router) {
			r.Use(api.requireAuthentication)
			r.Get("/", api.UserGet)
			r.With(sharedLimiter).Put("/", api.UserUpdate)
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

					r.Get("/", api.adminUserGet)
					r.Put("/", api.adminUserUpdate)
					r.Delete("/", api.adminUserDelete)
				})
			})

			r.Post("/generate_link", api.GenerateLink)
		})

		r.Route("/saml", func(r *router) {
			r.Route("/acs", func(r *router) {
				r.Use(api.loadSAMLState)
				r.Post("/", api.ExternalProviderCallback)
			})

			r.Get("/metadata", api.SAMLMetadata)
		})
	})

	if globalConfig.MultiInstanceMode {
		// Operator microservice API
		r.WithBypass(logger).Get("/", api.GetAppManifest)
		r.Route("/instances", func(r *router) {
			r.UseBypass(logger)

			r.Post("/", api.CreateInstance)
			r.Route("/{instance_id}", func(r *router) {
				r.Use(api.loadInstance)

				r.Get("/", api.GetInstance)
				r.Put("/", api.UpdateInstance)
				r.Delete("/", api.DeleteInstance)
			})
		})
	}

	corsHandler := cors.New(cors.Options{
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", audHeaderName, useCookieHeader},
		AllowCredentials: true,
	})

	api.handler = corsHandler.Handler(chi.ServerBaseContext(ctx, r))
	return api
}

// NewAPIFromConfigFile creates a new REST API using the provided configuration file.
func NewAPIFromConfigFile(filename string, version string) (*API, *conf.Configuration, error) {
	globalConfig, err := conf.LoadGlobal(filename)
	if err != nil {
		return nil, nil, err
	}

	config, err := conf.LoadConfig(filename)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := WithInstanceConfig(context.Background(), config, uuid.Nil)
	if err != nil {
		logrus.Fatalf("Error loading instance config: %+v", err)
	}

	db, err := storage.Dial(globalConfig)
	if err != nil {
		return nil, nil, err
	}

	return NewAPIWithVersion(ctx, globalConfig, db, version), config, nil
}

// HealthCheck endpoint indicates if the gotrue api service is available
func (a *API) HealthCheck(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, map[string]string{
		"version":     a.version,
		"name":        "GoTrue",
		"description": "GoTrue is a user registration and authentication API",
	})
}

// WithInstanceConfig adds the instanceID and tenant config to the context
func WithInstanceConfig(ctx context.Context, config *conf.Configuration, instanceID uuid.UUID) (context.Context, error) {
	ctx = withConfig(ctx, config)
	ctx = withInstanceID(ctx, instanceID)
	return ctx, nil
}

// Mailer returns NewMailer with the current tenant config
func (a *API) Mailer(ctx context.Context) mailer.Mailer {
	config := a.getConfig(ctx)
	return mailer.NewMailer(config)
}

func (a *API) getConfig(ctx context.Context) *conf.Configuration {
	obj := ctx.Value(configKey)
	if obj == nil {
		return nil
	}

	config := obj.(*conf.Configuration)

	// Merge global & per-instance external config for multi-instance mode
	if a.config.MultiInstanceMode {
		extConfig := (*a.config).External
		if err := mergo.MergeWithOverwrite(&extConfig, config.External); err != nil {
			return nil
		}
		config.External = extConfig

		// Merge global & per-instance smtp config for multi-instance mode
		smtpConfig := (*a.config).SMTP
		if err := mergo.MergeWithOverwrite(&smtpConfig, config.SMTP); err != nil {
			return nil
		}
		config.SMTP = smtpConfig
	}

	return config
}
