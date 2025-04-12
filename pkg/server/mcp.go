package server

import (
	"context"
	"fmt"
	"strings"

	dalfox "github.com/hahwul/dalfox/v2/lib"
	"github.com/hahwul/dalfox/v2/pkg/model"
	vlogger "github.com/hahwul/volt/logger"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// RunMCPServer starts the MCP server for Dalfox
func RunMCPServer(options model.Options) {
	vLog := vlogger.GetLogger(options.Debug)
	vLog.Info("Starting MCP Server")

	// Create a new MCP server
	s := mcpserver.NewMCPServer(
		"Dalfox XSS Scanner",
		"2.0.0",
		mcpserver.WithResourceCapabilities(true, true),
		mcpserver.WithLogging(),
		mcpserver.WithRecovery(),
	)

	// Add scan tool for standard URL scanning
	scanTool := mcp.NewTool("scan_with_dalfox",
		mcp.WithDescription("Scan for XSS vulnerabilities in a web application"),
		mcp.WithString("url",
			mcp.Required(),
			mcp.Description("The URL to scan for XSS vulnerabilities"),
		),
		mcp.WithString("method",
			mcp.Description("HTTP method to use (GET, POST, etc.)"),
			mcp.DefaultString("GET"),
		),
		mcp.WithString("headers",
			mcp.Description("Custom HTTP headers as a JSON string"),
		),
		mcp.WithString("cookie",
			mcp.Description("Cookies to include in the request"),
		),
		mcp.WithString("data",
			mcp.Description("HTTP request body for POST requests"),
		),
		mcp.WithBoolean("follow-redirects",
			mcp.Description("Whether to follow HTTP redirects"),
			mcp.DefaultBool(false),
		),
		mcp.WithString("proxy",
			mcp.Description("Proxy URL to route requests through"),
		),
		mcp.WithNumber("worker",
			mcp.Description("Number of concurrent worker threads"),
			mcp.DefaultNumber(100),
		),
		mcp.WithNumber("delay",
			mcp.Description("Delay between requests in milliseconds"),
			mcp.DefaultNumber(0),
		),
		mcp.WithBoolean("deep-domxss",
			mcp.Description("Enable deep DOM XSS testing"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("skip-discovery",
			mcp.Description("Skip the entire discovery phase, proceeding directly to XSS scanning"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("skip-mining-all",
			mcp.Description("Skip all parameter mining"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("skip-mining-dict",
			mcp.Description("Skip dictionary-based parameter mining"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("skip-mining-dom",
			mcp.Description("Skip DOM-based parameter mining"),
			mcp.DefaultBool(false),
		),
	)

	// Handler for the scan tool
	s.AddTool(scanTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		url := request.Params.Arguments["url"].(string)
		if url == "" {
			return nil, fmt.Errorf("URL is required")
		}

		// Create a unique scan ID
		sid := generateScanID(url)
		vLog.WithField("scan_id", sid).Info("Starting scan for URL: " + url)

		// Set up scan options
		rqOptions := model.Options{}

		// Parse optional parameters
		if method, ok := request.Params.Arguments["method"].(string); ok && method != "" {
			rqOptions.Method = method
		}

		if headers, ok := request.Params.Arguments["headers"].(string); ok && headers != "" {
			rqOptions.Header = strings.Split(headers, "|")
		}

		if cookie, ok := request.Params.Arguments["cookie"].(string); ok && cookie != "" {
			rqOptions.Cookie = cookie
		}

		if data, ok := request.Params.Arguments["data"].(string); ok && data != "" {
			rqOptions.Data = data
		}

		if followRedirect, ok := request.Params.Arguments["follow-redirects"].(bool); ok {
			rqOptions.FollowRedirect = followRedirect
		}

		if proxy, ok := request.Params.Arguments["proxy"].(string); ok && proxy != "" {
			rqOptions.ProxyAddress = proxy
		}

		if worker, ok := request.Params.Arguments["worker"].(float64); ok {
			rqOptions.Concurrence = int(worker)
		}

		if delay, ok := request.Params.Arguments["delay"].(float64); ok {
			rqOptions.Delay = int(delay)
		}

		if deepDomXSS, ok := request.Params.Arguments["deep-domxss"].(bool); ok {
			rqOptions.UseDeepDXSS = deepDomXSS
		}

		if skipDiscovery, ok := request.Params.Arguments["skip-discovery"].(bool); ok {
			rqOptions.SkipDiscovery = skipDiscovery
		}

		if skipMiningAll, ok := request.Params.Arguments["skip-mining-all"].(bool); ok {
			if skipMiningAll {
				rqOptions.Mining = false
				rqOptions.FindingDOM = false
			}
		}

		if skipMiningDict, ok := request.Params.Arguments["skip-mining-dict"].(bool); ok {
			if skipMiningDict {
				rqOptions.Mining = false
			}
		}

		if skipMiningDOM, ok := request.Params.Arguments["skip-mining-dom"].(bool); ok {
			if skipMiningDOM {
				rqOptions.FindingDOM = false
			}
		}

		// Create a goroutine to run the scan
		go func() {
			// Set up the target
			target := dalfox.Target{
				URL:     url,
				Method:  rqOptions.Method,
				Options: dalfox.Options{},
			}

			// Initialize options
			newOptions := dalfox.Initialize(target, target.Options)
			newOptions.Scan = options.Scan

			// Set method
			if rqOptions.Method != "" {
				newOptions.Method = rqOptions.Method
			} else {
				newOptions.Method = "GET"
			}

			// Clean URL
			escapedURL := url
			vLog.WithField("data1", sid).Debug(escapedURL)
			vLog.WithField("data1", sid).Debug(newOptions)

			// Run scan
			ScanFromAPI(url, newOptions, options, sid)
			vLog.WithField("data1", sid).Info("Scan completed successfully")
		}()

		// Return immediate response while scan runs in background
		return mcp.NewToolResultText(fmt.Sprintf("Scan started with ID: %s. The scan is running in the background.", sid)), nil
	})

	// Add results tool to get scan results
	resultsTool := mcp.NewTool("get_results_dalfox",
		mcp.WithDescription("Get results of a previously started scan"),
		mcp.WithString("scan_id",
			mcp.Required(),
			mcp.Description("The scan ID returned from the scan tool"),
		),
	)

	// Handler for the results tool
	s.AddTool(resultsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scanID := request.Params.Arguments["scan_id"].(string)
		if scanID == "" {
			return nil, fmt.Errorf("scan_id is required")
		}

		scan := GetScan(scanID, options)

		if len(scan.URL) == 0 {
			return mcp.NewToolResultText("Scan is still in progress. Please check again later."), nil
		}

		// Format results
		var resultText strings.Builder
		resultText.WriteString(fmt.Sprintf("Scan results for %s\n\n", scan.URL))

		if scan.Results == nil || len(scan.Results) == 0 {
			resultText.WriteString("No vulnerabilities found.")
		} else {
			resultText.WriteString("Vulnerabilities found:\n")
			for i, result := range scan.Results {
				resultText.WriteString(fmt.Sprintf("%d. %s\n", i+1, result))
			}
		}

		return mcp.NewToolResultText(resultText.String()), nil
	})

	// Start the MCP server over stdin/stdout
	if err := mcpserver.ServeStdio(s); err != nil {
		vLog.Error("MCP Server error:", err)
	}
}

// generateScanID creates a unique scan ID for MCP scans
func generateScanID(url string) string {
	return fmt.Sprintf("mcp-%s", strings.Replace(
		strings.Replace(url, "://", "-", -1),
		"/", "-", -1,
	))
}
