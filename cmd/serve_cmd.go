package cmd

import (
	"context"
	"net"
	"time"

	"net/http"

	// #nosec
	_ "net/http/pprof"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/supabase/gotrue/internal/api"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/utilities"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		serve(cmd.Context())
	},
}

func serve(ctx context.Context) {
	config, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.WithError(err).Fatal("unable to load config")
	}

	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("error opening database: %+v", err)
	}
	defer db.Close()

	// Run separate server for profiler
	if config.Profiler.Enabled {
		go func() {
			server := &http.Server{
				Addr:              config.Profiler.Addr,
				ReadHeaderTimeout: 2 * time.Second,
			}
			err := server.ListenAndServe()
			if err != nil {
				logrus.Warning("error running profiler: ", err)
			}
		}()
	}
	api := api.NewAPIWithVersion(ctx, config, db, utilities.Version)

	addr := net.JoinHostPort(config.API.Host, config.API.Port)
	logrus.Infof("GoTrue API started on: %s", addr)

	api.ListenAndServe(ctx, addr)
}
