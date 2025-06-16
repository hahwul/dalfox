package cmd

import (
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command which displays the current DalFox version
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.DalLog("YELLOW", printing.VERSION, options)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Apply custom help format to this subcommand for consistent help display
	ApplySubCommandCustomHelp(versionCmd)
}
