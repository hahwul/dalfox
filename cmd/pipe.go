package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

// pipeCmd represents the pipe command
var pipeCmd = &cobra.Command{
	Use:   "pipe [flags]",
	Short: "Use pipeline mode",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.Summary(options, "Stdin (pipeline)")
		var targets []string
		sc := bufio.NewScanner(os.Stdin)
		printing.DalLog("SYSTEM", "Using pipeline mode", options)
		for sc.Scan() {
			target := strings.ToLower(sc.Text())
			targets = append(targets, target)
		}
		targets = unique(targets)
		printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls", options)

		multi, _ := cmd.Flags().GetBool("multicast")
		if multi {
			printing.DalLog("SYSTEM", "Using multicasting mode", options)
			options.Silence = true
			t := scanning.MakeTargetSlice(targets)
			var wg sync.WaitGroup
			tt := 0
			for k, v := range t {
				printing.DalLog("SYSTEM-M", "Parallel testing to '"+k+"' => "+strconv.Itoa(len(v))+" urls", options)
				tt = tt + len(v)
			}
			s := spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
			s.Prefix = " "
			s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][0%] Parallel scanning from pipe"
			options.SpinnerObject = s
			if !options.NoColor {
				s.Color("red", "bold")
			}
			s.Start()
			options.NowURL = 0
			for k, v := range t {
				wg.Add(1)
				go func(k string, v []string) {
					defer wg.Done()
					for i := range v {
						scanning.Scan(v[i], options, strconv.Itoa(len(v)))
						mutex := &sync.Mutex{}
						mutex.Lock()
						options.NowURL = options.NowURL + 1
						percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(tt)*100)
						s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][" + percent + "] Parallel scanning from pipe"
						mutex.Unlock()
					}
				}(k, v)
			}
			wg.Wait()
			s.Stop()
		} else {
			options.AllURLS = len(targets)
			for i := range targets {
				options.NowURL = i + 1
				scanning.Scan(targets[i], options, strconv.Itoa(i))
			}

		}

	},
}

func init() {
	rootCmd.AddCommand(pipeCmd)
	pipeCmd.Flags().Bool("multicast", false, "Parallel scanning N*Host mode (show only poc code)")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pipeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pipeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
