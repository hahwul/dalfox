package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hahwul/dalfox/pkg/model"
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/spf13/cobra"
)

var cfgFile string
var optionsStr = make(map[string]string)
var optionsBool = make(map[string]bool)
var config, cookie, data, header, p, customPayload, userAgent, blind, output, format, foundAction, proxy, grep string
var ignoreReturn, miningWord, method string
var timeout, concurrence, delay int
var onlyDiscovery, silence, followRedirect, mining, findingDOM, noColor, noSpinner, onlyCustomPayload bool
var options model.Options
var skipMiningDom, skipMiningDict, skipMiningAll, skipXSSScan, skipBAV, skipGrep bool

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
	rootCmd.PersistentFlags().StringVarP(&blind, "blind", "b", "", "Add your blind xss (e.g -b hahwul.xss.ht)")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Write to output file")
	rootCmd.PersistentFlags().StringVar(&format, "format", "plain", "Stdout output format(plain/json)")
	rootCmd.PersistentFlags().StringVar(&foundAction, "found-action", "", "If found weak/vuln, action(cmd) to next")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "Send all request to proxy server (e.g --proxy http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().StringVar(&grep, "grep", "", "Using custom grepping file (e.g --grep ./samples/sample_grep.json)")
	rootCmd.PersistentFlags().StringVar(&ignoreReturn, "ignore-return", "", "Ignore scanning from return code (e.g --ignore-return 302,403,404)")
	rootCmd.PersistentFlags().StringVar(&miningWord, "mining-dict-word", "", "Custom wordlist file for param mining (e.g --mining-dict-word word.txt)")
	rootCmd.PersistentFlags().StringVarP(&method, "method", "X", "", "Force overriding HTTP Method (e.g -X PUT)")

	//Int
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "Second of timeout")
	rootCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Milliseconds between send to same host (1000==1s)")
	rootCmd.PersistentFlags().IntVarP(&concurrence, "worker", "w", 100, "Number of worker")

	//Bool
	rootCmd.PersistentFlags().BoolVar(&onlyDiscovery, "only-discovery", false, "Only testing parameter analysis (same '--skip-xss-scanning' option)")
	rootCmd.PersistentFlags().BoolVar(&silence, "silence", false, "Not printing all logs")
	rootCmd.PersistentFlags().BoolVar(&mining, "mining-dict", true, "Find new parameter with dictionary attack, default is Gf-Patterns=>XSS")
	rootCmd.PersistentFlags().BoolVar(&findingDOM, "mining-dom", true, "Find new parameter in DOM (attribute/js value)")
	rootCmd.PersistentFlags().BoolVar(&followRedirect, "follow-redirects", false, "Following redirection")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Not use colorize")
	rootCmd.PersistentFlags().BoolVar(&noSpinner, "no-spinner", false, "Not use spinner")
	rootCmd.PersistentFlags().BoolVar(&skipBAV, "skip-bav", false, "Skipping BAV(Basic Another Vulnerability) analysis")
	rootCmd.PersistentFlags().BoolVar(&skipMiningDom, "skip-mining-dom", false, "Skipping DOM base parameter mining")
	rootCmd.PersistentFlags().BoolVar(&skipMiningDict, "skip-mining-dict", false, "Skipping Dict base parameter mining")
	rootCmd.PersistentFlags().BoolVar(&skipMiningAll, "skip-mining-all", false, "Skipping ALL parameter mining")
	rootCmd.PersistentFlags().BoolVar(&skipXSSScan, "skip-xss-scanning", false, "Skipping XSS Scanning (same '--only-discovery' option)")
	rootCmd.PersistentFlags().BoolVar(&onlyCustomPayload, "only-custom-payload", false, "Only testing custom payload (required --custom-payload)")
	rootCmd.PersistentFlags().BoolVar(&skipGrep, "skip-grepping", false, "Skipping built-in grepping")

	printing.Banner()
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	options = model.Options{
		Header:            header,
		Cookie:            cookie,
		UniqParam:         p,
		BlindURL:          blind,
		CustomPayloadFile: customPayload,
		Data:              data,
		UserAgent:         userAgent,
		OutputFile:        output,
		Format:            format,
		FoundAction:       foundAction,
		ProxyAddress:      proxy,
		Grep:              grep,
		IgnoreReturn:      ignoreReturn,
		Timeout:           timeout,
		Concurrence:       concurrence,
		Delay:             delay,
		OnlyDiscovery:     onlyDiscovery,
		OnlyCustomPayload: onlyCustomPayload,
		Silence:           silence,
		FollowRedirect:    followRedirect,
		Scan:              make(map[string]model.Scan),
		Mining:            mining,
		MiningWordlist:    miningWord,
		FindingDOM:        findingDOM,
		NoColor:           noColor,
		Method:            method,
		NoSpinner:         noSpinner,
		NoBAV:             skipBAV,
		NoGrep:            skipGrep,
	}
	// var skipMiningDom, skipMiningDict, skipMiningAll, skipXSSScan, skipBAV bool

	if skipMiningAll {
		options.FindingDOM = false
		options.Mining = false

	} else {
		if skipMiningDom {
			options.FindingDOM = false
		}
		if skipMiningDict {
			options.Mining = false
		}
	}

	if skipXSSScan {
		options.OnlyDiscovery = true
	}

	if grep != "" {
		// Open our jsonFile
		jsonFile, err := os.Open(grep)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		printing.DalLog("SYSTEM", "Loaded "+grep+" file for grepping", options)
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()
		byteValue, _ := ioutil.ReadAll(jsonFile)
		options.Grep = string(byteValue)

	}

	if config != "" {
		// Open our jsonFile
		jsonFile, err := os.Open(config)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		printing.DalLog("SYSTEM", "Loaded "+config+" file for config option", options)
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal([]byte(byteValue), options)
	}

}
