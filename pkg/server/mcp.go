package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/utils"
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
		printing.VERSION,
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
		mcp.WithBoolean("output-request",
			mcp.Description("Include http request in the output"),
			mcp.DefaultBool(false),
		),
		mcp.WithBoolean("output-response",
			mcp.Description("Include http response in the output"),
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
		sid := utils.GenerateRandomToken(url)
		vLog.WithField("scan_id", sid).Info("Starting scan for URL: " + url)

		// Set up scan options
		rqOptions := model.Options{}

		// Parse optional parameters using maps similar to func.go pattern
		// Handle string options that require direct assignment
		stringOptions := map[string]struct {
			paramName string
			setter    func(string)
		}{
			"method": {"method", func(v string) { rqOptions.Method = v }},
			"cookie": {"cookie", func(v string) { rqOptions.Cookie = v }},
			"data":   {"data", func(v string) { rqOptions.Data = v }},
			"proxy":  {"proxy", func(v string) { rqOptions.ProxyAddress = v }},
		}

		for _, opt := range stringOptions {
			if value, ok := request.Params.Arguments[opt.paramName].(string); ok && value != "" {
				opt.setter(value)
			}
		}

		// Handle special case for headers which requires splitting
		if headers, ok := request.Params.Arguments["headers"].(string); ok && headers != "" {
			rqOptions.Header = strings.Split(headers, "|")
		}

		// Handle numeric options (converting from float64)
		numericOptions := map[string]struct {
			paramName string
			setter    func(int)
		}{
			"worker": {"worker", func(v int) { rqOptions.Concurrence = v }},
			"delay":  {"delay", func(v int) { rqOptions.Delay = v }},
		}

		for _, opt := range numericOptions {
			if value, ok := request.Params.Arguments[opt.paramName].(float64); ok {
				opt.setter(int(value))
			}
		}

		// Handle boolean options
		boolOptions := map[string]struct {
			paramName string
			setter    func(bool)
		}{
			"follow-redirects": {"follow-redirects", func(v bool) { rqOptions.FollowRedirect = v }},
			"deep-domxss":      {"deep-domxss", func(v bool) { rqOptions.UseDeepDXSS = v }},
			"skip-discovery":   {"skip-discovery", func(v bool) { rqOptions.SkipDiscovery = v }},
			"output-request":   {"output-request", func(v bool) { rqOptions.OutputRequest = v }},
			"output-response":  {"output-response", func(v bool) { rqOptions.OutputResponse = v }},
		}

		for _, opt := range boolOptions {
			if value, ok := request.Params.Arguments[opt.paramName].(bool); ok {
				opt.setter(value)
			}
		}

		// Handle special cases for mining options
		if skipMiningAll, ok := request.Params.Arguments["skip-mining-all"].(bool); ok && skipMiningAll {
			rqOptions.Mining = false
			rqOptions.FindingDOM = false
		}

		if skipMiningDict, ok := request.Params.Arguments["skip-mining-dict"].(bool); ok && skipMiningDict {
			rqOptions.Mining = false
		}

		if skipMiningDOM, ok := request.Params.Arguments["skip-mining-dom"].(bool); ok && skipMiningDOM {
			rqOptions.FindingDOM = false
		}

		// Create a goroutine to run the scan
		go func() {
			// Set up the target
			target := dalfox.Target{
				URL:     url,
				Method:  rqOptions.Method,
				Options: rqOptions,
			}

			// Initialize options using the pattern from func.go
			newOptions := dalfox.Initialize(target, target.Options)

			// Keep scan options from parent context
			newOptions.Scan = options.Scan

			// Default to GET if method not specified
			if newOptions.Method == "" {
				newOptions.Method = "GET"
			}

			// Run scan
			ScanFromAPI(url, newOptions, options, sid)
			vLog.WithField("scan_id", sid).Info("Scan completed successfully")
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

		// Define JSON structure for vulnerabilities
		type Vulnerability struct {
			ID              int    `json:"id"`
			Type            string `json:"type"`
			InjectType      string `json:"inject_type"`
			PoCType         string `json:"poc_type"`
			Method          string `json:"method"`
			Data            string `json:"data"`
			Param           string `json:"param"`
			Payload         string `json:"payload"`
			Evidence        string `json:"evidence"`
			CWE             string `json:"cwe"`
			Severity        string `json:"severity"`
			MessageID       int    `json:"message_id"`
			MessageStr      string `json:"message_str"`
			RawHTTPRequest  string `json:"raw_http_request"`
			RawHTTPResponse string `json:"raw_http_response"`
		}

		// Format results
		var resultText strings.Builder
		resultText.WriteString(fmt.Sprintf("Scan results for %s\n\n", scan.URL))

		if scan.Results == nil || len(scan.Results) == 0 {
			resultText.WriteString("No vulnerabilities found.")
		} else {
			// Prepare vulnerabilities array
			var vulnerabilities []Vulnerability
			for i, result := range scan.Results {
				vuln := Vulnerability{
					ID:              i + 1,
					Type:            result.Type,
					InjectType:      result.InjectType,
					PoCType:         result.PoCType,
					Method:          result.Method,
					Data:            result.Data,
					Param:           result.Param,
					Payload:         result.Payload,
					Evidence:        result.Evidence,
					CWE:             result.CWE,
					Severity:        result.Severity,
					MessageID:       int(result.MessageID),
					MessageStr:      result.MessageStr,
					RawHTTPRequest:  result.RawHTTPRequest,
					RawHTTPResponse: result.RawHTTPResponse,
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}

			// Convert to JSON
			jsonData, err := json.MarshalIndent(vulnerabilities, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal JSON: %v", err)
			}

			resultText.WriteString("Vulnerabilities found:\n")
			resultText.Write(jsonData)
		}

		return mcp.NewToolResultText(resultText.String()), nil
	})

	// Start the MCP server over stdin/stdout
	if err := mcpserver.ServeStdio(s); err != nil {
		vLog.Error("MCP Server error:", err)
	}
}
