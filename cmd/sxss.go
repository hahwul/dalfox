package cmd

import (
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/scanning"
	"github.com/spf13/cobra"
	"strconv"
)

var trigger string
var sequence int
var mass bool

// sxssCmd represents the sxss command
var sxssCmd = &cobra.Command{
	Use:   "sxss [target] [flags]",
	Short: "Use Stored XSS mode",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			printing.DalLog("SYSTEM", "Using Stored XSS mode", optionsStr)
			scanning.Scan(args[0], optionsStr, optionsBool)
		} else {
			printing.DalLog("ERROR", "Input target url", optionsStr)
			printing.DalLog("ERROR", "e.g dalfox sxss https://google.com/?q=1 --trigger https://target/profile", optionsStr)
		}
	},
}

func init() {
	rootCmd.AddCommand(sxssCmd)

	//Str
	sxssCmd.PersistentFlags().StringVar(&trigger, "trigger", "", "Checking this url after inject sxss code (e.g --trigger https://~~/profile)")

	//Int
	sxssCmd.PersistentFlags().IntVar(&sequence, "sequence", -1, "Set sequence to first number (e.g --trigger https://~/view?no=SEQNC --sequence 3)")

	//Int
	sxssCmd.PersistentFlags().BoolVar(&mass, "mass", false, "Testing mass vector (comming soon)")

	optionsStr["trigger"] = trigger
	optionsStr["sequence"] = strconv.Itoa(sequence)
	optionsBool["mass"] = mass
}
