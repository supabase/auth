package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/supabase/gotrue/internal/utilities"
)

var versionCmd = cobra.Command{
	Run: showVersion,
	Use: "version",
}

func showVersion(cmd *cobra.Command, args []string) {
	fmt.Println(utilities.Version)
}
