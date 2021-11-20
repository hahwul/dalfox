package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

// pipeCmd represents the pipe command
var pipeCmd = &cobra.Command{
	Use:   "pipe [flags]",
	Short: "Use pipeline mode",
	Run: func(cmd *cobra.Command, args []string) {
		sf, _ := cmd.Flags().GetBool("silence-force")
		if sf {
			options.Silence = sf
		}
		printing.Banner(options)
		printing.Summary(options, "Stdin (pipeline)")
		var targets []string
		mutex := &sync.Mutex{}
		options.Mutex = mutex
		sc := bufio.NewScanner(os.Stdin)
		if (!options.NoSpinner || !options.Silence) && !sf {
			options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
		}
		printing.DalLog("SYSTEM", "Using pipeline mode", options)
		for sc.Scan() {
			target := sc.Text()
			targets = append(targets, target)
		}
		targets = unique(targets)
		printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls", options)

		multi, _ := cmd.Flags().GetBool("multicast")
		mass, _ := cmd.Flags().GetBool("mass")
		if multi || mass {
			printing.DalLog("SYSTEM", "Using multicasting mode", options)
			options.Silence = true
			options.MulticastMode = true
			t := scanning.MakeTargetSlice(targets)
			tt := 0
			for k, v := range t {
				_ = k
				tt = tt + len(v)
			}
			if (!options.NoSpinner || !options.Silence) && !sf {
				options.SpinnerObject.Prefix = " "
				options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][0%] Parallel scanning from pipe"
				if !options.NoColor {
					options.SpinnerObject.Color("red", "bold")
				}
				options.SpinnerObject.Start()
			}
			var wg sync.WaitGroup
			tasks := make(chan model.MassJob)
			options.NowURL = 0
			concurrency, _ := cmd.Flags().GetInt("mass-worker")
			for k, v := range t {
				if !options.Silence || !sf {
					printing.DalLog("SYSTEM-M", "Parallel testing to '"+k+"' => "+strconv.Itoa(len(v))+" urls", options)
				}
			}
			for task := 0; task < concurrency; task++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for kv := range tasks {
						v := kv.URLs
						for i := range v {
							_, _ = scanning.Scan(v[i], options, strconv.Itoa(len(v)))
							if (!options.NoSpinner || !options.Silence) && !sf {
								options.Mutex.Lock()
								options.NowURL = options.NowURL + 1
								percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(tt)*100)
								options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][" + percent + "] Parallel scanning from pipe"
								options.Mutex.Unlock()
							}
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
			if (!options.NoSpinner || !options.Silence) && !sf {
				options.SpinnerObject.Stop()
			}
			if !options.Silence || !sf {
				printing.DalLog("SYSTEM-M", "Finish massive scan!", options)
			}
		} else {
			options.AllURLS = len(targets)
			if (!options.NoSpinner || !options.Silence) && !sf {
				options.SpinnerObject.Prefix = " "
				options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][0%] Multiple scanning from pipe"
				if !options.NoColor {
					options.SpinnerObject.Color("red", "bold")
				}
				options.SpinnerObject.Start()
			}
			for i := range targets {
				options.NowURL = i + 1
				_, _ = scanning.Scan(targets[i], options, strconv.Itoa(i))
				if (!options.NoSpinner || !options.Silence) && !sf {
					mutex.Lock()
					options.NowURL = options.NowURL + 1
					percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(options.AllURLS)*100)
					options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent + "] Multiple scanning from pipe"
					mutex.Unlock()
				}
			}
			if (!options.NoSpinner || !options.Silence) && !sf {
				options.SpinnerObject.Stop()
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(pipeCmd)
	pipeCmd.Flags().Bool("multicast", false, "Parallel scanning N*Host mode (show only poc code)")
	pipeCmd.Flags().Bool("mass", false, "Parallel scanning N*Host mode (show only poc code)")
	pipeCmd.Flags().Bool("silence-force", false, "Only print PoC (not print progress)")
	pipeCmd.Flags().Int("mass-worker", 10, "Parallel worker of --mass and --multicast option")
}
