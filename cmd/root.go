package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/har"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

var options model.Options
var harFilePath string
var args Args

var rootCmd = &cobra.Command{
	Use: "dalfox",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.DalLog("YELLOW", "Read the help page using the -h flag to see other options and flags!", options)
	},
}

// Execute is run rootCmd
func Execute() {
	defer func() {
		if options.HarWriter != nil {
			options.HarWriter.Close()
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Slice
	rootCmd.PersistentFlags().StringSliceVarP(&args.Header, "header", "H", []string{}, "Add custom headers")
	rootCmd.PersistentFlags().StringSliceVarP(&args.P, "param", "p", []string{}, "Only testing selected parameters")
	rootCmd.PersistentFlags().StringSliceVar(&args.IgnoreParams, "ignore-param", []string{}, "Ignores this parameter when scanning.\n  * Example: --ignore-param api_token --ignore-param csrf_token")

	// String
	rootCmd.PersistentFlags().StringVar(&args.Config, "config", "", "Using config from file")
	rootCmd.PersistentFlags().StringVarP(&args.Cookie, "cookie", "C", "", "Add custom cookie")
	rootCmd.PersistentFlags().StringVarP(&args.Data, "data", "d", "", "Using POST Method and add Body data")
	rootCmd.PersistentFlags().StringVar(&args.CustomPayload, "custom-payload", "", "Add custom payloads from file")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertValue, "custom-alert-value", "1", "Change alert value\n  * Example: --custom-alert-value=document.cookie")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertType, "custom-alert-type", "none", "Change alert value type\n  * Example: --custom-alert-type=none / --custom-alert-type=str,none")
	rootCmd.PersistentFlags().StringVar(&args.UserAgent, "user-agent", "", "Add custom UserAgent")
	rootCmd.PersistentFlags().StringVarP(&args.Blind, "blind", "b", "", "Add your blind xss\n  * Example: -b your-callback-url")
	rootCmd.PersistentFlags().StringVarP(&args.Output, "output", "o", "", "Write to output file (By default, only the PoC code is saved)")
	rootCmd.PersistentFlags().StringVar(&args.Format, "format", "plain", "Stdout output format\n  * Supported: plain / json")
	rootCmd.PersistentFlags().StringVar(&args.FoundAction, "found-action", "", "If found weak/vuln, action(cmd) to next\n  * Example: --found-action='./notify.sh'")
	rootCmd.PersistentFlags().StringVar(&args.FoundActionShell, "found-action-shell", "bash", "Select shell application for --found-action")
	rootCmd.PersistentFlags().StringVar(&args.Proxy, "proxy", "", "Send all request to proxy server\n  * Example: --proxy http://127.0.0.1:8080")
	rootCmd.PersistentFlags().StringVar(&args.Grep, "grep", "", "Using custom grepping file\n  * Example: --grep ./samples/sample_grep.json")
	rootCmd.PersistentFlags().StringVar(&args.IgnoreReturn, "ignore-return", "", "Ignores scanning from return code\n  * Example: --ignore-return 302,403,404")
	rootCmd.PersistentFlags().StringVarP(&args.MiningWord, "mining-dict-word", "W", "", "Custom wordlist file for param mining\n  * Example: --mining-dict-word word.txt")
	rootCmd.PersistentFlags().StringVarP(&args.Method, "method", "X", "GET", "Force overriding HTTP Method\n  * Example: -X PUT")
	rootCmd.PersistentFlags().StringVarP(&args.CookieFromRaw, "cookie-from-raw", "", "", "Load cookie from burp raw http request\n  * Example: --cookie-from-raw request.txt")
	rootCmd.PersistentFlags().StringVar(&args.RemotePayloads, "remote-payloads", "", "Using remote payload for XSS testing\n  * Supported: portswigger/payloadbox\n  * Example: --remote-payloads=portswigger,payloadbox")
	rootCmd.PersistentFlags().StringVar(&args.RemoteWordlists, "remote-wordlists", "", "Using remote wordlists for param mining\n  * Supported: burp/assetnote\n  * Example: --remote-wordlists=burp")
	rootCmd.PersistentFlags().StringVar(&args.OnlyPoC, "only-poc", "", "Shows only the PoC code for the specified pattern (g: grep / r: reflected / v: verified)\n * Example: --only-poc='g,v'")
	rootCmd.PersistentFlags().StringVar(&args.PoCType, "poc-type", "plain", "Select PoC type \n * Supported: plain/curl/httpie/http-request\n * Example: --poc-type='curl'")
	rootCmd.PersistentFlags().StringVar(&args.ReportFormat, "report-format", "plain", "Format of --report flag [plain/json]")
	rootCmd.PersistentFlags().StringVar(&args.HarFilePath, "har-file-path", "", "Path to save HAR of scan requests to")

	// Int
	rootCmd.PersistentFlags().IntVar(&args.Timeout, "timeout", 10, "Second of timeout")
	rootCmd.PersistentFlags().IntVar(&args.Delay, "delay", 0, "Milliseconds between send to same host (1000==1s)")
	rootCmd.PersistentFlags().IntVarP(&args.Concurrence, "worker", "w", 100, "Number of worker")

	// Bool
	rootCmd.PersistentFlags().BoolVar(&args.OnlyDiscovery, "only-discovery", false, "Only testing parameter analysis (same '--skip-xss-scanning' option)")
	rootCmd.PersistentFlags().BoolVarP(&args.Silence, "silence", "S", false, "Only print PoC Code and Progress(for pipe/file mode)")
	rootCmd.PersistentFlags().BoolVar(&args.Mining, "mining-dict", true, "Find new parameter with dictionary attack, default is Gf-Patterns=>XSS")
	rootCmd.PersistentFlags().BoolVar(&args.FindingDOM, "mining-dom", true, "Find new parameter in DOM (attribute/js value)")
	rootCmd.PersistentFlags().BoolVarP(&args.FollowRedirect, "follow-redirects", "F", false, "Following redirection")
	rootCmd.PersistentFlags().BoolVar(&args.NoColor, "no-color", false, "Not use colorize")
	rootCmd.PersistentFlags().BoolVar(&args.NoSpinner, "no-spinner", false, "Not use spinner")
	rootCmd.PersistentFlags().BoolVar(&args.UseBAV, "use-bav", false, "Use BAV(Basic Another Vulnerability) analysis")
	rootCmd.PersistentFlags().BoolVar(&args.SkipBAV, "skip-bav", false, "Skipping BAV(Basic Another Vulnerability) analysis")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDom, "skip-mining-dom", false, "Skipping DOM base parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDict, "skip-mining-dict", false, "Skipping Dict base parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningAll, "skip-mining-all", false, "Skipping ALL parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipXSSScan, "skip-xss-scanning", false, "Skipping XSS Scanning (same '--only-discovery' option)")
	rootCmd.PersistentFlags().BoolVar(&args.OnlyCustomPayload, "only-custom-payload", false, "Only testing custom payload (required --custom-payload)")
	rootCmd.PersistentFlags().BoolVar(&args.SkipGrep, "skip-grepping", false, "Skipping built-in grepping")
	rootCmd.PersistentFlags().BoolVar(&args.Debug, "debug", false, "debug mode, save all log using -o option")
	rootCmd.PersistentFlags().BoolVar(&args.SkipHeadless, "skip-headless", false, "Skipping headless browser base scanning[DOM XSS and inJS verify]")
	rootCmd.PersistentFlags().BoolVar(&args.UseDeepDXSS, "deep-domxss", false, "DOM XSS Testing with more payloads on headless [so slow]")
	rootCmd.PersistentFlags().BoolVar(&args.OutputAll, "output-all", false, "All log write mode (-o or stdout)")
	rootCmd.PersistentFlags().BoolVar(&args.WAFEvasion, "waf-evasion", false, "Avoid blocking by adjusting the speed when detecting WAF (worker=1 delay=3s)")
	rootCmd.PersistentFlags().BoolVar(&args.ReportBool, "report", false, "Show detail report")
	rootCmd.PersistentFlags().BoolVar(&args.OutputRequest, "output-request", false, "Include raw HTTP requests in the results.")
	rootCmd.PersistentFlags().BoolVar(&args.OutputResponse, "output-response", false, "Include raw HTTP response in the results.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	stime := time.Now()
	au := aurora.NewAurora(!args.NoColor)
	options = model.Options{
		Header:            args.Header,
		Cookie:            args.Cookie,
		UniqParam:         args.P,
		BlindURL:          args.Blind,
		CustomPayloadFile: args.CustomPayload,
		CustomAlertValue:  args.CustomAlertValue,
		CustomAlertType:   args.CustomAlertType,
		Data:              args.Data,
		UserAgent:         args.UserAgent,
		OutputFile:        args.Output,
		Format:            args.Format,
		FoundAction:       args.FoundAction,
		FoundActionShell:  args.FoundActionShell,
		ProxyAddress:      args.Proxy,
		Grep:              args.Grep,
		IgnoreReturn:      args.IgnoreReturn,
		IgnoreParams:      args.IgnoreParams,
		Timeout:           args.Timeout,
		Concurrence:       args.Concurrence,
		Delay:             args.Delay,
		OnlyDiscovery:     args.OnlyDiscovery,
		OnlyCustomPayload: args.OnlyCustomPayload,
		Silence:           args.Silence,
		FollowRedirect:    args.FollowRedirect,
		Scan:              make(map[string]model.Scan),
		Mining:            args.Mining,
		MiningWordlist:    args.MiningWord,
		FindingDOM:        args.FindingDOM,
		NoColor:           args.NoColor,
		Method:            args.Method,
		NoSpinner:         args.NoSpinner,
		NoBAV:             args.SkipBAV,
		NoGrep:            args.SkipGrep,
		Debug:             args.Debug,
		CookieFromRaw:     args.CookieFromRaw,
		AuroraObject:      au,
		StartTime:         stime,
		MulticastMode:     false,
		RemotePayloads:    args.RemotePayloads,
		RemoteWordlists:   args.RemoteWordlists,
		UseHeadless:       !args.SkipHeadless,
		UseDeepDXSS:       args.UseDeepDXSS,
		OnlyPoC:           args.OnlyPoC,
		OutputAll:         args.OutputAll,
		WAF:               false,
		WAFEvasion:        args.WAFEvasion,
		PoCType:           args.PoCType,
		ReportBool:        args.ReportBool,
		ReportFormat:      args.ReportFormat,
		OutputRequest:     args.OutputRequest,
		OutputResponse:    args.OutputResponse,
		UseBAV:            args.UseBAV,
	}

	if args.HarFilePath != "" {
		initHarWriter()
	}

	if args.SkipMiningAll {
		options.FindingDOM = false
		options.Mining = false
	} else {
		if args.SkipMiningDom {
			options.FindingDOM = false
		}
		if args.SkipMiningDict {
			options.Mining = false
		}
	}

	if args.SkipXSSScan {
		options.OnlyDiscovery = true
	}

	if args.Grep != "" {
		loadFile(args.Grep, "grepping")
	}

	if args.Config != "" {
		loadFile(args.Config, "config option")
	}
}

func initHarWriter() {
	f, err := os.Create(harFilePath)
	if err != nil {
		fmt.Println(err)
	} else {
		options.HarWriter, err = har.NewWriter(f, &har.Creator{Name: "dalfox", Version: printing.VERSION})
		if err != nil {
			fmt.Println(err)
		}
	}
}

func loadFile(filePath, fileType string) {
	jsonFile, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	printing.DalLog("SYSTEM", "Loaded "+filePath+" file for "+fileType, options)
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	if fileType == "config option" {
		err = json.Unmarshal(byteValue, &options)
		if err != nil {
			printing.DalLog("SYSTEM", "Error while parsing config file", options)
		}
	} else {
		options.Grep = string(byteValue)
	}
}
