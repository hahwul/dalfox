package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/blang/semver"
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update DalFox (Binary patch)",
	Run: func(cmd *cobra.Command, args []string) {
		confirmAndSelfUpdate()
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func confirmAndSelfUpdate() {
	version := printing.VERSION[1:]
	latest, found, err := selfupdate.DetectLatest("hahwul/dalfox")
	if err != nil {
		printing.DalLog("ERROR", "Error occurred while detecting version", optionsStr)
		return
	}

	v := semver.MustParse(version)
	if !found || latest.Version.LTE(v) {
		printing.DalLog("SYSTEM", "Current version is the latest", optionsStr)
		return
	}

	fmt.Print("Do you want to update to v", latest.Version, "? (y/n): ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || (input != "y\n" && input != "n\n") {
		printing.DalLog("ERROR", "Invalid input", optionsStr)
		return
	}
	if input == "n\n" {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		printing.DalLog("SYSTEM", "Could not locate executable path", optionsStr)
		return
	}
	if err := selfupdate.UpdateTo(latest.AssetURL, exe); err != nil {
		printing.DalLog("SYSTEM", "Error occurred while updating binary", optionsStr)
		return
	}
	printing.DalLog("SYSTEM", "Successfully updated to latest version", optionsStr)
}
