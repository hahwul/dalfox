package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	spinner "github.com/briandowns/spinner"
	model "github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
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
		printing.Summary(options, args[0])
		var targets []string
		mutex := &sync.Mutex{}
		options.Mutex = mutex
		if len(args) >= 1 {
			rawdata, _ := cmd.Flags().GetBool("rawdata")
			if rawdata {
				printing.DalLog("SYSTEM", "Using file mode(rawdata)", options)
				ff, err := readLinesOrLiteral(args[0])
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

			} else {
				printing.DalLog("SYSTEM", "Using file mode(targets list)", options)
				if (!options.NoSpinner || !options.Silence) && !sf {
					options.SpinnerObject = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
				}
				ff, err := readLinesOrLiteral(args[0])
				_ = err
				for _, target := range ff {
					targets = append(targets, target)
				}

				// Remove Deplicated value
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
						options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][0%] Multiple scanning from file"
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
							options.SpinnerObject.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent + "] Multiple scanning from file"
							mutex.Unlock()
						}
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
	fileCmd.Flags().Bool("rawdata", false, "Using req rawdata from Burp/ZAP")
	fileCmd.Flags().Bool("http", false, "Using force http on rawdata mode")
	fileCmd.Flags().Bool("multicast", false, "Parallel scanning N*Host mode (show only poc code)")
	fileCmd.Flags().Bool("mass", false, "Parallel scanning N*Host mode (show only poc code)")
	fileCmd.Flags().Bool("silence-force", false, "Only print PoC (not print progress)")
	fileCmd.Flags().Int("mass-worker", 10, "Parallel worker of --mass and --multicast option")
}

// a slice of strings, returning the slice and any error
func readLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	lines := make([]string, 0)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	return lines, sc.Err()
}

// readLinesOrLiteral tries to read lines from a file, returning
// the arg in a string slice if the file doesn't exist, unless
// the arg matches its default value
func readLinesOrLiteral(arg string) ([]string, error) {
	if isFile(arg) {
		return readLines(arg)
	}

	// if the argument isn't a file, but it is the default, don't
	// treat it as a literal value

	return []string{arg}, nil
}

// isFile returns true if its argument is a regular file
func isFile(path string) bool {
	f, err := os.Stat(path)
	return err == nil && f.Mode().IsRegular()
}

// unique is ..
func unique(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
