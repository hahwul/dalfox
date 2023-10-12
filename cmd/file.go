package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	spinner "github.com/briandowns/spinner"
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
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
	Run: func(cmd *cobra.Command, args []string) {
		sf, _ := cmd.Flags().GetBool("silence-force")
		if sf {
			options.Silence = sf
		}
		printing.Banner(options)
		tMethod := options.Method
		options.Method = "FILE Mode"
		if len(args) == 0 {
			printing.DalLog("ERROR", "Input file path", options)
			printing.DalLog("ERROR", "e.g dalfox file ./targets.txt or ./rawdata.raw", options)
			return
		}
		printing.Summary(options, args[0])
		options.Method = tMethod
		var targets []string
		mutex := &sync.Mutex{}
		options.Mutex = mutex
		if len(args) >= 1 {
			rawdata, _ := cmd.Flags().GetBool("rawdata")
			har, _ := cmd.Flags().GetBool("har")
			if rawdata {
				printing.DalLog("SYSTEM", "Using file mode(rawdata)", options)
				ff, err := voltFile.ReadLinesOrLiteral(args[0])
				_ = err
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
						printing.DalLog("ERROR", "HTTP Raw Request Format Error - Not found Host", options)
						os.Exit(1)
					}
					if http {
						target = "http://" + host + path
					} else {
						target = "https://" + host + path
					}
				}
				_, _ = scanning.Scan(target, options, "single")

			} else if har {
				printing.DalLog("SYSTEM", "Using file mode(targets list from HAR)", options)
				if (!options.NoSpinner || !options.Silence) && !sf {
					options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
				}
				var harObject voltHar.HARObject
				harFile, err := ioutil.ReadFile(args[0])
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
						if (!options.NoSpinner || !options.Silence) && !sf {
							mutex.Lock()
							options.NowURL = options.NowURL + 1
							percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(options.AllURLS)*100)
							options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent + "] Multiple scanning from file"
							mutex.Unlock()
						}
					}
					if options.Format == "json" {
						printing.DalLog("PRINT", "{}]", options)
					}
					if (!options.NoSpinner || !options.Silence) && !sf {
						options.SpinnerObject.Stop()
					}
				}

			} else {
				printing.DalLog("SYSTEM", "Using file mode(targets list)", options)
				if (!options.NoSpinner || !options.Silence) && !sf {
					options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
				}

				ff, err := voltFile.ReadLinesOrLiteral(args[0])
				_ = err
				targets = append(targets, ff...)

				// Remove Deplicated value
				targets = voltUtils.UniqueStringSlice(targets)
				printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls", options)
				multi, _ := cmd.Flags().GetBool("multicast")
				mass, _ := cmd.Flags().GetBool("mass")
				if multi || mass {
					printing.DalLog("SYSTEM", "Using multicasting mode", options)
					options.Silence = true
					options.MulticastMode = true
					t := scanning.MakeTargetSlice(targets)
					tt := 0
					//mutex := &sync.Mutex{}

					for k, v := range t {
						_ = k
						tt = tt + len(v)
					}
					if (!options.NoSpinner || !options.Silence) && !sf {
						options.SpinnerObject.Prefix = " "
						options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][0%] Parallel scanning from file"
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
										mutex.Lock()
										options.NowURL = options.NowURL + 1
										percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(tt)*100)
										options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(tt) + " Tasks][" + percent + "] Parallel scanning from file"
										mutex.Unlock()
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
				} else {
					options.AllURLS = len(targets)
					if (!options.NoSpinner || !options.Silence) && !sf {
						options.SpinnerObject.Prefix = " "
						options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][0%] Multiple scanning from file"
						if !options.NoColor {
							options.SpinnerObject.Color("red", "bold")
						}
						options.SpinnerObject.Start()
					}
					if options.Format == "json" {
						printing.DalLog("PRINT", "[", options)
					}
					for i := range targets {
						options.NowURL = i + 1
						_, _ = scanning.Scan(targets[i], options, strconv.Itoa(i))
						if (!options.NoSpinner || !options.Silence) && !sf {
							mutex.Lock()
							options.NowURL = options.NowURL + 1
							percent := fmt.Sprintf("%0.2f%%", float64(options.NowURL)/float64(options.AllURLS)*100)
							options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent + "] Multiple scanning from file"
							mutex.Unlock()
						}
					}
					if options.Format == "json" {
						printing.DalLog("PRINT", "{}]", options)
					}
					if (!options.NoSpinner || !options.Silence) && !sf {
						options.SpinnerObject.Stop()
					}
				}
			}
		} else {
			printing.DalLog("ERROR", "Input file path", options)
			printing.DalLog("ERROR", "e.g dalfox file ./targets.txt or ./rawdata.raw", options)
		}
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
	fileCmd.Flags().Bool("rawdata", false, "[FORMAT] Using req rawdata from Burp/ZAP")
	fileCmd.Flags().Bool("har", false, "[FORMAT] Using HAR format")
	fileCmd.Flags().Bool("http", false, "Using force http on rawdata mode")
	fileCmd.Flags().Bool("multicast", false, "Parallel scanning N*Host mode (show only poc code)")
	fileCmd.Flags().Bool("mass", false, "Parallel scanning N*Host mode (show only poc code)")
	fileCmd.Flags().Bool("silence-force", false, "Only print PoC (not print progress)")
	fileCmd.Flags().Int("mass-worker", 10, "Parallel worker of --mass and --multicast option")
}
