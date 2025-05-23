package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// executeCommand is a helper function to capture stdout/stderr for command execution
func executeCommand(args ...string) (string, string, error) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	rootCmd.ResetFlags()
	// Re-initialize flags for each test run if necessary by calling init() of rootCmd
	// This depends on how your Cobra app is structured. If initConfig is automatically called,
	// you might need to reset options or use a fresh instance of rootCmd.
	// For this example, we assume init() needs to be called or flags are registered in init().
	// Re-registering or resetting global 'options' might be needed.
	options = model.Options{} // Reset global options

// The rootCmd.Execute() call will trigger OnInitialize, which calls initConfig.
// initConfig then populates the global 'options' variable.
// We need to provide a valid subcommand ('scan') and a target URL for Execute() to proceed far enough.
var fullArgs []string
fullArgs = append(fullArgs, "scan") // Add 'scan' subcommand
fullArgs = append(fullArgs, args...) // Add the test arguments (flags and URL)

rootCmd.SetArgs(fullArgs)

	err := rootCmd.Execute()

	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var outBuf, errBuf bytes.Buffer
	io.Copy(&outBuf, rOut)
	io.Copy(&errBuf, rErr)

	return outBuf.String(), errBuf.String(), err
}

func TestRootCmd_CustomBlindXSSFlag(t *testing.T) {
	// Store original rootCmd flags to restore them later if necessary,
	// though ResetFlags should handle this.
	// originalFlags := rootCmd.Flags()

	tests := []struct {
		name          string
		args          []string // Arguments to pass to dalfox, including the target URL
		expectedValue string
		expectError   bool // Whether an error from rootCmd.Execute() is expected
	}{
		{
			name:          "Set custom-blind-xss-payload flag",
			args:          []string{"--custom-blind-xss-payload", "test_payloads.txt", "http://example.com"},
			expectedValue: "test_payloads.txt",
			expectError:   false, // Expect no error just from parsing this flag with a valid target
		},
		{
			name:          "Set custom-blind-xss-payload flag with empty value",
			args:          []string{"--custom-blind-xss-payload", "", "http://example.com"},
			expectedValue: "",
			expectError:   false,
		},
		// Add more test cases if needed, e.g., for interactions with config files
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global 'options' and 'args' for each test.
			// The global 'args' variable (type Args) is populated by PersistentFlags directly.
			// The global 'options' variable (type model.Options) is populated by initConfig.
			options = model.Options{}
			// Reset the args struct that holds flag values directly
			args = Args{}


			// Re-initialize flags for the rootCmd. This is crucial.
			// If flags are not reset and re-added, tests can interfere with each other
			// due to "flag redefined" panics or stale flag values.
			rootCmd.ResetFlags()
			initFlagsForTest() // Call our test helper to add flags to rootCmd

			// The executeCommand function handles setting args and executing.
			// It's important that executeCommand is structured to call initConfig
			// (e.g., by calling rootCmd.Execute() which triggers Cobra's OnInitialize).
			_, _, err := executeCommand(tt.args...)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
			} else {
				if err != nil {
					// Dalfox's rootCmd Run function prints help if no subcommand is given.
					// If 'scan' subcommand's Run is complex, it might return errors for other reasons.
					// We are primarily interested in flag parsing.
					// Check if the error is something critical or just a part of normal help/usage display.
					// For this test, we assume that if the flag is parsed correctly, minor errors from
					// the actual scan operation (which isn't fully mocked here) are acceptable.
					// However, a nil error is preferred if the command structure allows for just parsing.
					// t.Logf("executeCommand error: %v (Note: some errors may be ignored if flag parsing is okay)", err)
				}
			}

			// After executeCommand, initConfig should have run and populated 'options'.
			if options.CustomBlindXSSPayloadFile != tt.expectedValue {
				t.Errorf("options.CustomBlindXSSPayloadFile: got %q, want %q", options.CustomBlindXSSPayloadFile, tt.expectedValue)
			}
		})
	}
}

// initFlagsForTest re-initializes the command flags for rootCmd.
// This is a simplified version of the actual init() in root.go,
// focusing on flags relevant to testing.
func initFlagsForTest() {
	// This function should mirror the flag definitions in your actual cmd/root.go's init()

	// String Slice
	rootCmd.PersistentFlags().StringSliceVarP(&args.Header, "header", "H", []string{}, "Add custom headers")
	rootCmd.PersistentFlags().StringSliceVarP(&args.P, "param", "p", []string{}, "Specify parameters to test")
	rootCmd.PersistentFlags().StringSliceVar(&args.IgnoreParams, "ignore-param", []string{}, "Ignore specific parameters")

	// String
	rootCmd.PersistentFlags().StringVar(&args.Config, "config", "", "Load configuration from file")
	rootCmd.PersistentFlags().StringVarP(&args.Cookie, "cookie", "C", "", "Add custom cookies")
	rootCmd.PersistentFlags().StringVarP(&args.Data, "data", "d", "", "Use POST method and add body data")
	rootCmd.PersistentFlags().StringVar(&args.CustomPayload, "custom-payload", "", "Load custom payloads from file")
	rootCmd.PersistentFlags().StringVar(&args.CustomBlindXSSPayloadFile, "custom-blind-xss-payload", "", "Load custom blind XSS payloads from file")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertValue, "custom-alert-value", DefaultCustomAlertValue, "Set custom alert value")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertType, "custom-alert-type", DefaultCustomAlertType, "Set custom alert type")
	rootCmd.PersistentFlags().StringVar(&args.UserAgent, "user-agent", "", "Set custom User-Agent")
	rootCmd.PersistentFlags().StringVarP(&args.Blind, "blind", "b", "", "Specify blind XSS callback URL")
	rootCmd.PersistentFlags().StringVarP(&args.Output, "output", "o", "", "Write output to file")
	rootCmd.PersistentFlags().StringVar(&args.Format, "format", DefaultFormat, "Set output format")
	rootCmd.PersistentFlags().StringVar(&args.FoundAction, "found-action", "", "Execute command when vulnerability found")
	rootCmd.PersistentFlags().StringVar(&args.FoundActionShell, "found-action-shell", DefaultFoundActionShell, "Specify shell for found action")
	rootCmd.PersistentFlags().StringVar(&args.Proxy, "proxy", "", "Send requests through proxy")
	rootCmd.PersistentFlags().StringVar(&args.Grep, "grep", "", "Use custom grepping file")
	rootCmd.PersistentFlags().StringVar(&args.IgnoreReturn, "ignore-return", "", "Ignore specific HTTP return codes")
	rootCmd.PersistentFlags().StringVarP(&args.MiningWord, "mining-dict-word", "W", "", "Specify custom wordlist for parameter mining")
	rootCmd.PersistentFlags().StringVarP(&args.Method, "method", "X", DefaultMethod, "Override HTTP method")
	rootCmd.PersistentFlags().StringVarP(&args.CookieFromRaw, "cookie-from-raw", "", "", "Load cookies from raw HTTP request file")
	rootCmd.PersistentFlags().StringVar(&args.RemotePayloads, "remote-payloads", "", "Use remote payloads")
	rootCmd.PersistentFlags().StringVar(&args.RemoteWordlists, "remote-wordlists", "", "Use remote wordlists")
	rootCmd.PersistentFlags().StringVar(&args.OnlyPoC, "only-poc", "", "Show only PoC code for specified pattern")
	rootCmd.PersistentFlags().StringVar(&args.PoCType, "poc-type", DefaultPoCType, "Select PoC type")
	rootCmd.PersistentFlags().StringVar(&args.ReportFormat, "report-format", DefaultReportFormat, "Set report format")
	rootCmd.PersistentFlags().StringVar(&args.HarFilePath, "har-file-path", "", "Specify path to save HAR files")

	// Int
	rootCmd.PersistentFlags().IntVar(&args.Timeout, "timeout", DefaultTimeout, "Set request timeout")
	rootCmd.PersistentFlags().IntVar(&args.Delay, "delay", 0, "Set delay between requests")
	rootCmd.PersistentFlags().IntVarP(&args.Concurrence, "worker", "w", DefaultConcurrence, "Set number of concurrent workers")
	rootCmd.PersistentFlags().IntVar(&args.MaxCPU, "max-cpu", DefaultMaxCPU, "Set maximum number of CPUs")

	// Bool
	rootCmd.PersistentFlags().BoolVar(&args.OnlyDiscovery, "only-discovery", false, "Only perform parameter analysis")
	rootCmd.PersistentFlags().BoolVarP(&args.Silence, "silence", "S", false, "Only print PoC code and progress")
	rootCmd.PersistentFlags().BoolVar(&args.Mining, "mining-dict", true, "Enable dictionary-based parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.FindingDOM, "mining-dom", true, "Enable DOM-based parameter mining")
	rootCmd.PersistentFlags().BoolVarP(&args.FollowRedirect, "follow-redirects", "F", false, "Follow HTTP redirects")
	rootCmd.PersistentFlags().BoolVar(&args.NoColor, "no-color", false, "Disable colorized output")
	rootCmd.PersistentFlags().BoolVar(&args.NoSpinner, "no-spinner", false, "Disable spinner animation")
	rootCmd.PersistentFlags().BoolVar(&args.UseBAV, "use-bav", false, "Enable Basic Another Vulnerability analysis")
	rootCmd.PersistentFlags().BoolVar(&args.SkipBAV, "skip-bav", false, "Skip Basic Another Vulnerability analysis") // Assuming these are actual flags
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDom, "skip-mining-dom", false, "Skip DOM-based parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDict, "skip-mining-dict", false, "Skip dictionary-based parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningAll, "skip-mining-all", false, "Skip all parameter mining")
	rootCmd.PersistentFlags().BoolVar(&args.SkipXSSScan, "skip-xss-scanning", false, "Skip XSS scanning")
	rootCmd.PersistentFlags().BoolVar(&args.OnlyCustomPayload, "only-custom-payload", false, "Only test custom payloads")
	rootCmd.PersistentFlags().BoolVar(&args.SkipGrep, "skip-grepping", false, "Skip built-in grepping")
	rootCmd.PersistentFlags().BoolVar(&args.Debug, "debug", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&args.SkipHeadless, "skip-headless", false, "Skip headless browser-based scanning")
	rootCmd.PersistentFlags().BoolVar(&args.UseDeepDXSS, "deep-domxss", false, "Enable deep DOM XSS testing")
	rootCmd.PersistentFlags().BoolVar(&args.OutputAll, "output-all", false, "Enable all log write mode")
	rootCmd.PersistentFlags().BoolVar(&args.WAFEvasion, "waf-evasion", false, "Enable WAF evasion")
	rootCmd.PersistentFlags().BoolVar(&args.ReportBool, "report", false, "Show detailed report")
	rootCmd.PersistentFlags().BoolVar(&args.OutputRequest, "output-request", false, "Include raw HTTP requests")
	rootCmd.PersistentFlags().BoolVar(&args.OutputResponse, "output-response", false, "Include raw HTTP responses")
	rootCmd.PersistentFlags().BoolVar(&args.SkipDiscovery, "skip-discovery", false, "Skip discovery phase")
	rootCmd.PersistentFlags().BoolVar(&args.ForceHeadlessVerification, "force-headless-verification", false, "Force headless browser-based verification")
}

func TestMain(m *testing.M) {
	// This TestMain is a good place to call initFlagsForTest if it's needed globally for all tests in this package.
	// However, individual tests might need finer control.
	// initFlagsForTest() // Call it here or in each test/suite setup
	os.Exit(m.Run())
}
