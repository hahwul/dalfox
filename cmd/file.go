package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	spinner "github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/internal/printing"
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	voltFile "github.com/hahwul/volt/file"
	voltHar "github.com/hahwul/volt/format/har"
	voltUtils "github.com/hahwul/volt/util"
	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file [filePath] [flags]",
	Short: "Use file mode(targets list or rawdata)",
	Run:   runFileCmd,
}

func runFileCmd(cmd *cobra.Command, args []string) {
	sf, _ := cmd.Flags().GetBool("silence-force")
	if sf {
		options.Silence = sf
	}
	printing.Banner(options)
	tMethod := options.Method
	options.Method = "FILE Mode"
	if len(args) == 0 {
		printFileErrorAndUsage()
		return
	}
	printing.Summary(options, args[0])
	options.Method = tMethod
	mutex := &sync.Mutex{}
	options.Mutex = mutex
	if len(args) >= 1 {
		rawdata, _ := cmd.Flags().GetBool("rawdata")
		har, _ := cmd.Flags().GetBool("har")
		if rawdata {
			runRawDataMode(args[0], cmd)
		} else if har {
			runHarMode(args[0], cmd, sf)
		} else {
			runFileMode(args[0], cmd, sf)
		}
	} else {
		printFileErrorAndUsage()
	}
}

func runRawDataMode(filePath string, cmd *cobra.Command) {
	printing.DalLog("SYSTEM", "Using file mode with raw data format", options)
	ff, err := voltFile.ReadLinesOrLiteral(filePath)
	if err != nil {
		printing.DalLog("ERROR", "Failed to read file: "+err.Error(), options)
		return
	}
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
			if strings.Index(line, "Host: ") != -1 {
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

func runHarMode(filePath string, cmd *cobra.Command, sf bool) {
	printing.DalLog("SYSTEM", "Using file mode with targets list from HAR", options)
	if (!options.NoSpinner || !options.Silence) && !sf {
		options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
	}
	var harObject voltHar.HARObject
	harFile, err := os.ReadFile(filePath)
	if err == nil {
		err = json.Unmarshal(harFile, &harObject)
		if options.Format == "json" {
			printing.DalLog("PRINT", "[", options)
		}
		for i, entry := range harObject.Log.Entries {
			var turl string
			options.NowURL = i + 1
			if len(entry.Request.QueryString) > 0 {
				var tquery string
				for _, query := range entry.Request.QueryString {
					tquery = tquery + query.Name + "=" + query.Value + "&"
				}
				turl = entry.Request.URL + "?" + tquery
			} else {
				turl = entry.Request.URL
			}
			if entry.Request.PostData.Text != "" {
				options.Data = entry.Request.PostData.Text
			}
			options.Method = entry.Request.Method
			_, _ = scanning.Scan(turl, options, strconv.Itoa(i))
			updateSpinner(options, sf, i, len(harObject.Log.Entries))
		}
		if options.Format == "json" {
			printing.DalLog("PRINT", "{}]", options)
		}
		if (!options.NoSpinner || !options.Silence) && !sf {
			options.SpinnerObject.Stop()
		}
	}
}

func runFileMode(filePath string, cmd *cobra.Command, sf bool) {
	printing.DalLog("SYSTEM", "Using file mode with targets list", options)
	if (!options.NoSpinner || !options.Silence) && !sf {
		options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
	}

	ff, err := voltFile.ReadLinesOrLiteral(filePath)
	if err != nil {
		printing.DalLog("ERROR", "Failed to read file: "+err.Error(), options)
		return
	}
	targets := voltUtils.UniqueStringSlice(ff)
	printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target URLs", options)
	multi, _ := cmd.Flags().GetBool("multicast")
	mass, _ := cmd.Flags().GetBool("mass")
	limit, _ := cmd.Flags().GetInt("limit")
	if multi || mass {
		runMulticastMode(targets, cmd, sf, limit)
	} else {
		runSingleMode(targets, sf, limit)
	}
}

func updateSpinner(options model.Options, sf bool, current, total int) {
	if (!options.NoSpinner || !options.Silence) && !sf {
		options.Mutex.Lock()
		options.NowURL++
		percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(total)*100)
		options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(total) + " Tasks][" + percent + "] Parallel scanning from file"
		options.Mutex.Unlock()
	}
}

func printFileErrorAndUsage() {
printing.DalLog("ERROR", "Please provide a valid target file (targets.txt or rawdata.raw)", options)
printing.DalLog("ERROR", "Example: dalfox file ./targets.txt or ./rawdata.raw", options)
}

func init() {
	rootCmd.AddCommand(fileCmd)
	fileCmd.Flags().Bool("rawdata", false, "[FORMAT] Use raw data from Burp/ZAP. Example: --rawdata")
	fileCmd.Flags().Bool("har", false, "[FORMAT] Use HAR format. Example: --har")
	fileCmd.Flags().Bool("http", false, "Force HTTP on raw data mode. Example: --http")
	fileCmd.Flags().Bool("multicast", false, "Enable parallel scanning in N*Host mode (only shows PoC code). Example: --multicast")
	fileCmd.Flags().Bool("mass", false, "Enable parallel scanning in N*Host mode (only shows PoC code). Example: --mass")
	fileCmd.Flags().Bool("silence-force", false, "Only print PoC code, suppress progress output. Example: --silence-force")
	fileCmd.Flags().Int("mass-worker", 10, "Set the number of parallel workers for --mass and --multicast options. Example: --mass-worker 10")
	fileCmd.Flags().Int("limit", 0, "Limit the number of results to display. Example: --limit 10")
}
