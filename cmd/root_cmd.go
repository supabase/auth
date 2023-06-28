package cmd

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/observability"
)

var configFile = ""

var rootCmd = cobra.Command{
	Use: "gotrue",
	Run: func(cmd *cobra.Command, args []string) {
		migrate(cmd, args)
		serve(cmd.Context())
	},
}

// RootCommand will setup and return the root command
func RootCommand() *cobra.Command {
	rootCmd.AddCommand(&serveCmd, &migrateCmd, &versionCmd, adminCmd())
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "the config file to use")

	return &rootCmd
}

func loadGlobalConfig(ctx context.Context) *conf.GlobalConfiguration {
	if ctx == nil {
		panic("context must not be nil")
	}

	config, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %+v", err)
	}

	if err := observability.ConfigureLogging(&config.Logging); err != nil {
		logrus.WithError(err).Error("unable to configure logging")
	}

	if err := observability.ConfigureTracing(ctx, &config.Tracing); err != nil {
		logrus.WithError(err).Error("unable to configure tracing")
	}

	if err := observability.ConfigureMetrics(ctx, &config.Metrics); err != nil {
		logrus.WithError(err).Error("unable to configure metrics")
	}

	if err := observability.ConfigureProfiler(ctx, &config.Profiler); err != nil {
		logrus.WithError(err).Error("unable to configure profiler")
	}
	return config
}

func execWithConfigAndArgs(cmd *cobra.Command, fn func(config *conf.GlobalConfiguration, args []string), args []string) {
	fn(loadGlobalConfig(cmd.Context()), args)
}
