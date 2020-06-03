package cmd

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/scanning"
	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file [filePath] [flags]",
	Short: "Use file mode(targets list or rawdata)",
	Run: func(cmd *cobra.Command, args []string) {
		var targets []string
		if len(args) >= 1 {
			rawdata, _ := cmd.Flags().GetBool("rawdata")
			if rawdata {
				printing.DalLog("SYSTEM", "Using file mode(rawdata)", optionsStr)
				ff, err := readLinesOrLiteral(args[0])
				_ = err
				var path, body, host, target string
				var headers []string
				bodyswitch := false
				for index, line := range ff {
					if index == 0 {
						parse := strings.Split(line, " ")
						path = parse[1]
					}
					_ = headers
					if strings.Index(line, "Host: ") != -1 {
						host = line[6:]
					}
					if strings.Index(line, "Cookie: ") != -1 {
						optionsStr["cookie"] = line[9:]
					}
					if strings.Index(line, "User-Agent: ") != -1 {
						optionsStr["ua"] = line[12:]
					}
					if bodyswitch {
						body = body + line
					}
					if len(line) == 0 {
						bodyswitch = true
					}
				}
				optionsStr["data"] = body
				http, _ := cmd.Flags().GetBool("http")
				if strings.Index(path, "http") == 0 {
					target = path
				} else {
					if http {
						target = "http://" + host + path
					} else {
						target = "https://" + host + path
					}
				}
				scanning.Scan(target, optionsStr, optionsBool)

			} else {
				printing.DalLog("SYSTEM", "Using file mode(targets list)", optionsStr)
				ff, err := readLinesOrLiteral(args[0])
				_ = err
				for _, target := range ff {
					targets = append(targets, target)
				}

				// Remove Deplicated value
				targets = unique(targets)
				printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls", optionsStr)
				multi, _ := cmd.Flags().GetBool("multicast")
				if multi {
					printing.DalLog("SYSTEM", "Using multicasting mode", optionsStr)
					t := scanning.MakeTargetSlice(targets)
					var wg sync.WaitGroup
					for k, v := range t {
						wg.Add(1)
						go func(k string, v []string) {
							defer wg.Done()
							printing.DalLog("SYSTEM", "testing to '"+k+"' => "+strconv.Itoa(len(v))+" urls", optionsStr)
							for i := range v {
								scanning.Scan(v[i], optionsStr, optionsBool)
							}
						}(k, v)
					}
					wg.Wait()
				} else {
					for i := range targets {
						scanning.Scan(targets[i], optionsStr, optionsBool)
					}

				}
			}
		} else {
			printing.DalLog("ERROR", "Input file path", optionsStr)
			printing.DalLog("ERROR", "e.g dalfox file ./targets.txt or ./rawdata.raw", optionsStr)
		}
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

	fileCmd.Flags().Bool("rawdata", false, "Using req rawdata from Burp/ZAP")
	fileCmd.Flags().Bool("http", false, "Using force http on rawdata mode")
	fileCmd.Flags().Bool("multicast", false, "Scanning N*Host mode")
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
