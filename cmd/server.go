package cmd

import (
	printing "github.com/hahwul/dalfox/v2/pkg/printing"
	server "github.com/hahwul/dalfox/v2/pkg/server"
	"github.com/spf13/cobra"
)

var port int
var host string

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start API Server",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.DalLog("SYSTEM", "Starting API Server", options)
		options.ServerHost = host
		options.ServerPort = port
		printing.Summary(options, "REST API Mode")
		server.RunAPIServer(options)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().IntVar(&port, "port", 6664, "Bind Port")
	serverCmd.Flags().StringVar(&host, "host", "0.0.0.0", "Bind address")
}
