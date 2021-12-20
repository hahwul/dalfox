package cmd

import (
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

var trigger, requestMethod string
var sequence int

// sxssCmd represents the sxss command
var sxssCmd = &cobra.Command{
	Use:   "sxss [target] [flags]",
	Short: "Use Stored XSS mode",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.Summary(options, args[0])
		if len(args) >= 1 {
			options.Trigger = trigger
			options.Sequence = sequence
			options.TriggerMethod = requestMethod
			options.Concurrence = 1
			if options.Delay <= 1500 {
				options.Delay = 1500
			}
			if options.Trigger != "" {
				printing.DalLog("SYSTEM", "Using Stored XSS mode", options)
				_, _ = scanning.Scan(args[0], options, "Single")
			} else {
				printing.DalLog("ERROR", "Please input trigger url with --trigger option", options)
			}
		} else {
			printing.DalLog("ERROR", "Input target url", options)
			printing.DalLog("ERROR", "e.g dalfox sxss https://google.com/?q=1 --trigger https://target/profile", options)
		}
	},
}

func init() {
	rootCmd.AddCommand(sxssCmd)
	sxssCmd.PersistentFlags().StringVar(&requestMethod, "request-method", "GET", "Request method send to the server")
	sxssCmd.PersistentFlags().StringVar(&trigger, "trigger", "", "Checking this url after inject sxss code\n  * Example: --trigger=https://~~/profile")
	sxssCmd.PersistentFlags().IntVar(&sequence, "sequence", -1, "Set sequence to first number\n  * Example: --trigger=https://~/view?no=SEQNC --sequence=3")
}
