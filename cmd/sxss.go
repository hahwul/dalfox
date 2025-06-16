package cmd

import (
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

// Command-line flags for stored XSS mode
var trigger, requestMethod string // Trigger URL and HTTP request method
var sequence int                  // Sequence number for URLs

// sxssCmd represents the stored XSS command for testing stored cross-site scripting vulnerabilities
var sxssCmd = &cobra.Command{
	Use:   "sxss [target] [flags]",
	Short: "Use Stored XSS mode",
	Run:   runSxssCmd,
}

// runSxssCmd handles execution of the stored XSS testing command
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

// printSXSSErrorAndUsage displays error messages and usage examples for the stored XSS command
func printSXSSErrorAndUsage() {
	printing.DalLog("ERROR", "Input target url", options)
	printing.DalLog("ERROR", "e.g dalfox sxss https://google.com/?q=1 --trigger https://target/profile", options)
}

// init registers the stored XSS command and its flags
func init() {
	rootCmd.AddCommand(sxssCmd)
	sxssCmd.PersistentFlags().StringVar(&requestMethod, "request-method", "GET", "Specify the HTTP request method to send to the server. Example: --request-method 'POST'")
	sxssCmd.PersistentFlags().StringVar(&trigger, "trigger", "", "Specify the URL to check after injecting SXSS code. Example: --trigger 'https://example.com/profile'")
	sxssCmd.PersistentFlags().IntVar(&sequence, "sequence", -1, "Set the initial sequence number for the trigger URL. Example: --trigger 'https://example.com/view?no=SEQNC' --sequence 3")

	// Apply custom help format to this subcommand
	ApplySubCommandCustomHelp(sxssCmd)
}
