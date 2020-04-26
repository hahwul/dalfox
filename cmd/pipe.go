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
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/scanning"
	"github.com/spf13/cobra"
)

// pipeCmd represents the pipe command
var pipeCmd = &cobra.Command{
	Use:   "pipe [flags]",
	Short: "Use pipeline mode",
	Run: func(cmd *cobra.Command, args []string) {
		var targets []string
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.ToLower(sc.Text())
			targets = append(targets, target)
		}
		targets = unique(targets)
		printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls")
		for i := range targets {
			scanning.Scan(targets[i], optionsStr, optionsBool)
		}
	},
}

func init() {
	rootCmd.AddCommand(pipeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pipeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pipeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
