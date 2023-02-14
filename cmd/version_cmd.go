package cmd

import (
	"fmt"

	"github.com/supabase/gotrue/internal/utilities"
	"github.com/spf13/cobra"
)

var versionCmd = cobra.Command{
	Run: showVersion,
	Use: "version",
}

func showVersion(cmd *cobra.Command, args []string) {
	fmt.Println(utilities.Version)
}
