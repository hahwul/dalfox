package cmd

import (
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

var trigger, requestMethod string
var sequence int

// sxssCmd represents the sxss command
var sxssCmd = &cobra.Command{
	Use:   "sxss [target] [flags]",
	Short: "Use Stored XSS mode",
	Run:   runSxssCmd,
}

func runSxssCmd(cmd *cobra.Command, args []string) {
	printing.Banner(options)
	if len(args) == 0 {
		printSXSSErrorAndUsage()
		return
	}

	printing.Summary(options, args[0])
	options.Trigger = trigger
	options.Sequence = sequence
	options.TriggerMethod = requestMethod
	options.Concurrence = 1
	if options.Delay <= 1500 {
		options.Delay = 1500
	}

	if options.Trigger != "" {
		printing.DalLog("SYSTEM", "Using Stored XSS mode", options)
		if options.Format == "json" {
			printing.DalLog("PRINT", "[", options)
		}
		_, _ = scanning.Scan(args[0], options, "Single")
		if options.Format == "json" {
			printing.DalLog("PRINT", "{}]", options)
		}
	} else {
		printing.DalLog("ERROR", "Please input trigger url with --trigger option", options)
	}
}

func printSXSSErrorAndUsage() {
	printing.DalLog("ERROR", "Input target url", options)
	printing.DalLog("ERROR", "e.g dalfox sxss https://google.com/?q=1 --trigger https://target/profile", options)
}

func init() {
	rootCmd.AddCommand(sxssCmd)
	sxssCmd.PersistentFlags().StringVar(&requestMethod, "request-method", "GET", "Specify the HTTP request method to send to the server. Example: --request-method 'POST'")
	sxssCmd.PersistentFlags().StringVar(&trigger, "trigger", "", "Specify the URL to check after injecting SXSS code. Example: --trigger 'https://example.com/profile'")
	sxssCmd.PersistentFlags().IntVar(&sequence, "sequence", -1, "Set the initial sequence number for the trigger URL. Example: --trigger 'https://example.com/view?no=SEQNC' --sequence 3")
}
