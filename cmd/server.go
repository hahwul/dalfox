package cmd

import (

	"github.com/spf13/cobra"
	. "github.com/hahwul/dalfox/pkg/server"
	printing "github.com/hahwul/dalfox/pkg/printing"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start API Server",
	Run: func(cmd *cobra.Command, args []string) {
		printing.DalLog("SYSTEM", "Starting API Server", options)
		RunAPIServer(options)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
