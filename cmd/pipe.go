package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/utils"
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	voltUtils "github.com/hahwul/volt/util"
	"github.com/spf13/cobra"
)

// pipeCmd represents the pipe command for processing targets from standard input
var pipeCmd = &cobra.Command{
	Use:   "pipe [flags]",
	Short: "Use pipeline mode",
	Run:   runPipeCmd,
}

// runPipeCmd handles execution of the pipe command for scanning targets from stdin
func runPipeCmd(cmd *cobra.Command, args []string) {
	sf, _ := cmd.Flags().GetBool("silence-force")
	if sf {
		options.Silence = sf
	}
	printing.Banner(options)
	tMethod := options.Method
	options.Method = "Pipe Mode"
	printing.Summary(options, "Stdin (pipeline)")
	options.Method = tMethod

	rawdata, _ := cmd.Flags().GetBool("rawdata")
	if rawdata {
		runRawDataPipeMode(cmd)
		return
	}

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
	targets = voltUtils.UniqueStringSlice(targets)
	printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls", options)

	multi, _ := cmd.Flags().GetBool("multicast")
	mass, _ := cmd.Flags().GetBool("mass")
	limit, _ := cmd.Flags().GetInt("limit")
	if multi || mass {
		runMulticastMode(targets, cmd, sf, limit)
	} else {
		runSingleMode(targets, sf, limit)
	}
}

// runRawDataPipeMode processes a file containing raw HTTP request data
func runRawDataPipeMode(cmd *cobra.Command) {
	printing.DalLog("SYSTEM", "Using pipe mode with raw data format", options)
	bytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		printing.DalLog("ERROR", "Failed to read from stdin: "+err.Error(), options)
		return
	}
	rawReq := string(bytes)

	// Check if the input is base64 encoded
	b64decoded, err := base64.StdEncoding.DecodeString(rawReq)
	if err == nil {
		rawReq = string(b64decoded)
	}

	ff := strings.Split(strings.ReplaceAll(rawReq, "\r\n", "\n"), "\n")

	var path, body, host, target string
	bodyswitch := false
	for index, line := range ff {
		if index == 0 {
			parse := strings.Split(line, " ")
			if len(parse) > 1 {
				options.Method = parse[0]
				path = parse[1]
			} else {
				printing.DalLog("ERROR", "HTTP Raw Request Format Error", options)
				os.Exit(1)
			}
		} else {
			if strings.Contains(line, "Host: ") || strings.Contains(line, "host: ") {
				host = line[6:]
			} else {
				parse := strings.Split(line, ":")
				if len(parse) > 1 {
					options.Header = append(options.Header, line)
				}
			}
			if bodyswitch {
				body = body + line
			}
			if len(line) == 0 {
				bodyswitch = true
			}
		}
	}
	options.Data = body
	http, _ := cmd.Flags().GetBool("http")
	if strings.Index(path, "http") == 0 {
		target = path
	} else {
		if host == "" {
			printing.DalLog("ERROR", "HTTP Raw Request Format Error - Host not found", options)
			os.Exit(1)
		}
		if http {
			target = "http://" + host + path
		} else {
			target = "https://" + host + path
		}
	}
	_, _ = scanning.Scan(target, options, "single")
}

// runMulticastMode processes multiple targets in parallel using worker pools
// It distributes scanning tasks across multiple goroutines for efficient processing
func runMulticastMode(targets []string, cmd *cobra.Command, sf bool, limit int) {
	printing.DalLog("SYSTEM", "Using multicasting mode", options)
	options.Silence = true
	options.MulticastMode = true
	t := utils.MakeTargetSlice(targets)
	tt := 0
	for _, v := range t {
		tt += len(v)
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
	var totalResults int
	var resultsMutex sync.Mutex
	var shouldStop bool

	for task := 0; task < concurrency; task++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for kv := range tasks {
				v := kv.URLs
				for i := range v {
					if shouldStop {
						break // Skip processing if we reached the limit
					}

					result, _ := scanning.Scan(v[i], options, strconv.Itoa(len(v)))

					if limit > 0 {
						resultsMutex.Lock()
						totalResults += len(result.PoCs)
						if totalResults >= limit {
							if !options.Silence || !sf {
								printing.DalLog("SYSTEM-M", "Result limit reached ("+strconv.Itoa(limit)+"). Stopping scan.", options)
							}
							shouldStop = true
						}
						resultsMutex.Unlock()
					}

					if (!options.NoSpinner || !options.Silence) && !sf {
						options.Mutex.Lock()
						options.NowURL++
						percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(tt)*100)
						options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][" + percent + "] Parallel scanning from pipe"
						options.Mutex.Unlock()
					}
				}
			}
		}()
	}
	if options.Format == "json" {
		printing.DalLog("PRINT", "[", options)
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
	if options.Format == "json" {
		printing.DalLog("PRINT", "{}]", options)
	}
	if (!options.NoSpinner || !options.Silence) && !sf {
		options.SpinnerObject.Stop()
	}
	if !options.Silence || !sf {
		printing.DalLog("SYSTEM-M", "Finish massive scan!", options)
	}
}

// runSingleMode processes targets sequentially one by one
// It's more resource-friendly but slower than multicast mode
func runSingleMode(targets []string, sf bool, limit int) {
	options.AllURLS = len(targets)

	if (!options.NoSpinner || !options.Silence) && !sf {
		options.SpinnerObject.Prefix = " "
		options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][0%] Multiple scanning from pipe"
		if !options.NoColor {
			options.SpinnerObject.Color("red", "bold")
		}
		options.SpinnerObject.Start()
	}
	var totalResults int
	var allResults []model.Result

	if options.Format == "json" {
		printing.DalLog("PRINT", "[", options)
	}
	for i := range targets {
		options.NowURL = i + 1
		result, _ := scanning.Scan(targets[i], options, strconv.Itoa(i))

		// Add the current result to our collection
		allResults = append(allResults, result)

		// Count total PoCs across all results
		totalResults = 0
		for _, res := range allResults {
			totalResults += len(res.PoCs)
		}

		if limit > 0 && totalResults >= limit {
			if !options.Silence || !sf {
				printing.DalLog("SYSTEM", "Result limit reached ("+strconv.Itoa(limit)+"). Stopping scan.", options)
			}
			break
		}

		if (!options.NoSpinner || !options.Silence) && !sf {
			options.Mutex.Lock()
			options.NowURL++
			percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(options.AllURLS)*100)
			options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent + "] Multiple scanning from pipe"
			options.Mutex.Unlock()
		}
	}
	if options.Format == "json" {
		printing.DalLog("PRINT", "{}]", options)
	}
	if (!options.NoSpinner || !options.Silence) && !sf {
		options.SpinnerObject.Stop()
	}
}

// init registers the pipe command and its flags
func init() {
	rootCmd.AddCommand(pipeCmd)
	pipeCmd.Flags().Bool("rawdata", false, "[FORMAT] Use raw data from Burp/ZAP. Example: --rawdata")
	pipeCmd.Flags().Bool("http", false, "Force HTTP on raw data mode. Example: --http")
	pipeCmd.Flags().Bool("multicast", false, "Enable parallel scanning in N*Host mode (only shows PoC code). Example: --multicast")
	pipeCmd.Flags().Bool("mass", false, "Enable parallel scanning in N*Host mode (only shows PoC code). Example: --mass")
	pipeCmd.Flags().Bool("silence-force", false, "Only print PoC code, suppress progress output. Example: --silence-force")
	pipeCmd.Flags().Int("mass-worker", 10, "Set the number of parallel workers for --mass and --multicast options. Example: --mass-worker 10")
	pipeCmd.Flags().Int("limit", 0, "Limit the number of results to display. Example: --limit 10")

	// Apply custom help format to this subcommand
	ApplySubCommandCustomHelp(pipeCmd)
}
