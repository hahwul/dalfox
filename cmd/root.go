package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/spf13/cobra"
)

var cfgFile string
var optionsStr = make(map[string]string)
var optionsBool = make(map[string]bool)
var config, cookie, data, header, p, customPayload, userAgent, blind, output, format, foundAction, proxy string
var timeout, concurrence, delay int
var onlyDiscovery bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "dalfox",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	printing.Banner()
	cobra.OnInitialize(initConfig)
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	//Str
	rootCmd.PersistentFlags().StringVar(&config, "config", "", "Using config from file")
	rootCmd.PersistentFlags().StringVarP(&cookie, "cookie", "C", "", "Add custom cookie")
	rootCmd.PersistentFlags().StringVarP(&data, "data", "d", "", "Using POST Method and add Body data")
	rootCmd.PersistentFlags().StringVarP(&header, "header", "H", "", "Add custom headers")
	rootCmd.PersistentFlags().StringVarP(&p, "param", "p", "", "Only testing selected parameters")
	rootCmd.PersistentFlags().StringVar(&customPayload, "custom-payload", "", "Add custom payloads from file")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "", "Add custom UserAgent")
	rootCmd.PersistentFlags().StringVarP(&blind, "blind", "b", "", "Add your blind xss")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Write to output file")
	rootCmd.PersistentFlags().StringVar(&format, "output-format", "", "-o/--output 's format (txt/json/xml)")
	rootCmd.PersistentFlags().StringVar(&foundAction, "found-action", "", "if found weak/vuln, action(cmd) to next")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "Send all request to proxy server")

	//Int
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "second of timeout (default 10sec)")
	rootCmd.PersistentFlags().IntVar(&delay, "delay", 0, "delay nano-second request (1000==1s)")
	rootCmd.PersistentFlags().IntVar(&concurrence, "concurrence", 20, "number of concurrence")

	//Bool
	rootCmd.PersistentFlags().BoolVar(&onlyDiscovery, "only-discovery", false, "Only testing parameter analysis")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	optionsStr["header"] = header
	optionsStr["cookie"] = cookie
	optionsStr["p"] = p
	optionsStr["blind"] = blind
	optionsStr["customPayload"] = customPayload
	optionsStr["data"] = data
	optionsStr["ua"] = userAgent
	optionsStr["output"] = output
	optionsStr["format"] = format
	optionsStr["foundAction"] = foundAction
	optionsStr["proxy"] = proxy
	optionsStr["timeout"] = strconv.Itoa(timeout)
	optionsStr["concurrence"] = strconv.Itoa(concurrence)
	optionsStr["delay"] = strconv.Itoa(delay)

	optionsBool["only-discovery"] = onlyDiscovery

	if config != "" {
		// Open our jsonFile
		jsonFile, err := os.Open(config)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		printing.DalLog("SYSTEM", "Using config options / loaded "+config+" file", optionsStr)
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}
		json.Unmarshal([]byte(byteValue), &result)

		for k, v := range result {
			if k == "blind" || k == "p" || k == "cookie" || k == "header" || k == "ua" {
				optionsStr[k] = v.(string)
			}
			if k == "only-discovery" || k == "pipe" {
				optionsBool[k] = v.(bool)
			}
		}
	}
}
