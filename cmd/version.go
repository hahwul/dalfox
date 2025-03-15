package cmd

import (
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
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
}
