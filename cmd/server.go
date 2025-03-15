package cmd

import (
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/server"
	"github.com/spf13/cobra"
)

var port int
var host string

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start API Server",
	Run:   runServerCmd,
}

func runServerCmd(cmd *cobra.Command, args []string) {
	printing.Banner(options)
	printing.DalLog("SYSTEM", "Starting API Server", options)
	options.ServerHost = host
	options.ServerPort = port
	printing.Summary(options, "REST API Mode")
	server.RunAPIServer(options)
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().IntVar(&port, "port", 6664, "Specify the port to bind the server to. Example: --port 6664")
	serverCmd.Flags().StringVar(&host, "host", "0.0.0.0", "Specify the address to bind the server to. Example: --host '0.0.0.0'")
}
