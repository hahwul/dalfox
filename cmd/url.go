/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
			printing.DalLog("SYSTEM", "Used single target mode")
			scanning.Scan(args[0], optionsStr, optionsBool)
		} else {
			printing.DalLog("ERROR", "Input target url")
			printing.DalLog("ERROR", "e.g dalfox url https://google.com/?q=1")
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
