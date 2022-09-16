package cmd

import (
	"context"
	"fmt"

	"github.com/netlify/gotrue/api"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/utilities"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		execWithConfig(cmd, serve)
	},
}

func serve(config *conf.GlobalConfiguration) {
	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("Error opening database: %+v", err)
	}
	defer db.Close()

	api := api.NewAPIWithVersion(context.Background(), config, db, utilities.Version)

	l := fmt.Sprintf("%v:%v", config.API.Host, config.API.Port)
	logrus.Infof("GoTrue API started on: %s", l)
	api.ListenAndServe(l)
}
