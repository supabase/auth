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
	a := api.NewAPIWithVersion(config, db, utilities.Version, opts...)
	ah := reloader.NewAtomicHandler(a)
	logrus.WithField("version", a.Version()).Infof("GoTrue API started on: %s", addr)

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           ah,
		ReadHeaderTimeout: 2 * time.Second, // to mitigate a Slowloris attack
		BaseContext: func(net.Listener) context.Context {
			return baseCtx
		},
	}
	log := logrus.WithField("component", "api")

	var wg sync.WaitGroup
	defer wg.Wait() // Do not return to caller until this goroutine is done.

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

		defer baseCancel() // close baseContext

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
	if err := httpSrv.Serve(listener); err != nil {
		log.WithError(err).Fatal("http server serve failed")
	}
}
