package cmd

import (
	"context"
	"net"

	"github.com/netlify/gotrue/api"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/utilities"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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

	api := api.NewAPIWithVersion(ctx, config, utilities.Version)
	db := api.Tenant.GetConnection()
	defer db.Close()
	addr := net.JoinHostPort(config.API.Host, config.API.Port)
	logrus.Infof("GoTrue API started on: %s", addr)

	api.ListenAndServe(ctx, addr)
}
