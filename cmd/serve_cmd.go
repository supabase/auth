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
	"github.com/supabase/auth/internal/api/worker"
	"github.com/supabase/auth/internal/conf"
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

	addr := net.JoinHostPort(config.API.Host, config.API.Port)

	opts := []api.Option{
		api.NewLimiterOptions(config),
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	var wg sync.WaitGroup
	defer wg.Wait() // Do not return to caller until this goroutine is done.

	if config.Worker.Enabled {
		wrkLog := logrus.WithField("component", "workers")
		wrk := worker.New(config, wrkLog)
		opts = append(opts, &api.MailerOptions{
			MailerClientFunc: wrk.GetMailerFunc,
		})

		wg.Add(1)
		go func() {
			defer wg.Done()

			var err error
			defer func() {
				logFn := wrkLog.Info
				if err != nil {
					logFn = wrkLog.WithError(err).Error
				}
				logFn("worker is exiting")
			}()

			// Work takes base context so it does not exit until the http server
			// has shutdown.
			err = wrk.Work(baseCtx)
		}()
	}

	a := api.NewAPIWithVersion(config, db, utilities.Version, opts...)
	ah := reloader.NewAtomicHandler(a)
	logrus.WithField("version", a.Version()).Infof("GoTrue API started on: %s", addr)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           ah,
		ReadHeaderTimeout: 2 * time.Second, // to mitigate a Slowloris attack
		BaseContext: func(net.Listener) context.Context {
			return baseCtx
		},
	}
	log := logrus.WithField("component", "api")

	if watchDir != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			fn := func(latestCfg *conf.GlobalConfiguration) {
				log.Info("reloading api with new configuration")
				latestAPI := api.NewAPIWithVersion(
					latestCfg, db, utilities.Version, opts...)
				ah.Store(latestAPI)
			}

			rl := reloader.NewReloader(watchDir)
			if err := rl.Watch(ctx, fn); err != nil {
				log.WithError(err).Error("watcher is exiting")
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
