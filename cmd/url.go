package cmd

import (
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/scanning"
	"github.com/spf13/cobra"
)

// urlCmd represents the url command
var urlCmd = &cobra.Command{
	Use:   "url [target] [flags]",
	Short: "Use single target mode",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			printing.DalLog("SYSTEM", "Using single target mode", optionsStr)
			scanning.Scan(args[0], optionsStr, optionsBool)
		} else {
			printing.DalLog("ERROR", "Input target url", optionsStr)
			printing.DalLog("ERROR", "e.g dalfox url https://google.com/?q=1", optionsStr)
		}
	},
}

func init() {
	rootCmd.AddCommand(urlCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// urlCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// urlCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
