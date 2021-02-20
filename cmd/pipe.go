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
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

var (
	mutex = &sync.Mutex{}
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
		mass, _ := cmd.Flags().GetBool("mass")
		if multi || mass {
			printing.DalLog("SYSTEM", "Using multicasting mode", options)
			options.Silence = true
			t := scanning.MakeTargetSlice(targets)

			tt := 0
			for k, v := range t {
				_ = k
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
			var wg sync.WaitGroup
			tasks := make(chan model.MassJob)
			options.NowURL = 0
			concurrency, _ := cmd.Flags().GetInt("mass-worker")
			for task := 0; task < concurrency; task++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for kv := range tasks {
						k := kv.Name
						v := kv.URLs
						printing.DalLog("SYSTEM-M", "Parallel testing to '"+k+"' => "+strconv.Itoa(len(v))+" urls", options)
						for i := range v {
							scanning.Scan(v[i], options, strconv.Itoa(len(v)))
							mutex := &sync.Mutex{}
							mutex.Lock()
							options.NowURL = options.NowURL + 1
							percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(tt)*100)
							s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][" + percent + "] Parallel scanning from pipe"
							mutex.Unlock()
						}
					}
				}()
			}
			for k, v := range t {
				temp := model.MassJob{
					Name: k,
					URLs: v,
				}
				tasks <- temp
			}
			close(tasks)
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
	pipeCmd.Flags().Bool("mass", false, "Parallel scanning N*Host mode (show only poc code)")
	pipeCmd.Flags().Int("mass-worker", 10, "Parallel worker of --mass and --multicast option")
}
