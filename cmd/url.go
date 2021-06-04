package cmd

import (
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

// urlCmd represents the url command
var urlCmd = &cobra.Command{
	Use:   "url [target] [flags]",
	Short: "Use single target mode",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.Summary(options, args[0])
		if len(args) >= 1 {
			printing.DalLog("SYSTEM", "Using single target mode", options)
			_, _ = scanning.Scan(args[0], options, "Single")
		} else {
			printing.DalLog("ERROR", "Input target url", options)
			printing.DalLog("ERROR", "e.g dalfox url https://google.com/?q=1", options)
		}
	},
}

func init() {
	rootCmd.AddCommand(urlCmd)
}
