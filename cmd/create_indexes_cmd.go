package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/supabase/auth/internal/indexworker"
)

var createIndexesCmd = cobra.Command{
	Use:   "create-indexes",
	Short: "Create indexes in the auth.users table",
	Long:  "Create indexes in the auth.users table to optimize user search operations.",
	Run:   createIndexes,
}

func createIndexes(cmd *cobra.Command, args []string) {
	config := loadGlobalConfig(cmd.Context())
	ctx := cmd.Context()
	indexworker.CreateIndexes(ctx, config, logrus.NewEntry(logrus.StandardLogger()))
}
