package cmd

import (
	"context"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/api/apiworker"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer/templatemailer"
	"github.com/supabase/auth/internal/reloader"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		serve(cmd.Context())
	},
}

func serve(ctx context.Context) {
	if err := conf.LoadFile(configFile); err != nil {
		logrus.WithError(err).Fatal("unable to load config")
	}

	if err := conf.LoadDirectory(watchDir); err != nil {
		logrus.WithError(err).Error("unable to load config from watch dir")
	}

	config, err := conf.LoadGlobalFromEnv()
	if err != nil {
		logrus.WithError(err).Fatal("unable to load config")
	}

	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("error opening database: %+v", err)
	}
	defer db.Close()

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	var wg sync.WaitGroup
	defer wg.Wait() // Do not return to caller until this goroutine is done.

	mrCache := templatemailer.NewCache()
	limiterOpts := api.NewLimiterOptions(config)
	initialAPI := api.NewAPIWithVersion(
		config, db, utilities.Version,
		limiterOpts,
		api.WithMailer(templatemailer.FromConfig(config, mrCache)),
	)

	addr := net.JoinHostPort(config.API.Host, config.API.Port)
	logrus.WithField("version", initialAPI.Version()).Infof("GoTrue API started on: %s", addr)

	ah := reloader.NewAtomicHandler(initialAPI)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           ah,
		ReadHeaderTimeout: 2 * time.Second, // to mitigate a Slowloris attack
		BaseContext: func(net.Listener) context.Context {
			return baseCtx
		},
	}
	log := logrus.WithField("component", "api")

	wrkLog := logrus.WithField("component", "apiworker")
	wrk := apiworker.New(config, mrCache, wrkLog)
	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		defer func() {
			logFn := wrkLog.Info
			if err != nil {
				logFn = wrkLog.WithError(err).Error
			}
			logFn("background apiworker is exiting")
		}()

		// Work exits when ctx is done as in-flight requests do not depend
		// on it. If they do in the future this should be baseCtx instead.
		err = wrk.Work(ctx)
	}()

	if watchDir != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			rc := config.Reloading
			le := logrus.WithFields(logrus.Fields{
				"component":             "reloader",
				"notify_enabled":        rc.NotifyEnabled,
				"poller_enabled":        rc.PollerEnabled,
				"poller_interval":       rc.PollerInterval.String(),
				"signal_enabled":        rc.SignalEnabled,
				"signal_number":         rc.SignalNumber,
				"grace_period_duration": rc.GracePeriodInterval.String(),
			})
			le.Info("starting configuration reloader")

			var err error
			defer func() {
				exitFn := le.Info
				if err != nil {
					exitFn = le.WithError(err).Error
				}
				exitFn("config reloader is exiting")
			}()

			fn := func(latestCfg *conf.GlobalConfiguration) {
				le.Info("reloading api with new configuration")

				// When config is updated we notify the apiworker.
				wrk.ReloadConfig(latestCfg)

				// Create a new API version with the updated config.
				latestAPI := api.NewAPIWithVersion(
					latestCfg, db, utilities.Version,

					// Create a new mailer with existing template cache.
					api.WithMailer(
						templatemailer.FromConfig(latestCfg, mrCache),
					),

					// Persist existing rate limiters.
					//
					// TODO(cstockton): we should consider updating these, if we
					// rely on hot config reloads 100% then rate limiter changes
					// won't be picked up.
					limiterOpts,
				)
				ah.Store(latestAPI)
			}

			rl := reloader.NewReloader(rc, watchDir)
			if err = rl.Watch(ctx, fn); err != nil {
				log.WithError(err).Error("config reloader is exiting")
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()

		// This must be done after httpSrv exits, otherwise you may potentially
		// have 1 or more inflight http requests blocked until the shutdownCtx
		// is canceled.
		defer baseCancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Minute)
		defer shutdownCancel()

		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.WithError(err).Error("shutdown failed")
		}
	}()

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		log.WithError(err).Fatal("http server listen failed")
	}
	err = httpSrv.Serve(listener)
	if err == http.ErrServerClosed {
		log.Info("http server closed")
	} else if err != nil {
		log.WithError(err).Fatal("http server serve failed")
	}
}
