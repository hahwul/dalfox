package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/internal/utils"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

// Mocking the ScanFromAPI function as it involves complex internal logic and network operations
var mockScanFromAPICalled bool
var mockScanFromAPIUrl string
var mockScanFromAPIOptions model.Options
var mockScanFromAPIScanID string

func TestMain(m *testing.M) {
	// Save original functions and defer their restoration
	originalServerScanFromAPI := serverScanFromAPI
	originalUtilsGenerateRandomToken := utilsGenerateRandomToken

	serverScanFromAPI = func(url string, newOptions model.Options, options model.Options, sid string) {
		mockScanFromAPICalled = true
		mockScanFromAPIUrl = url
		mockScanFromAPIOptions = newOptions
		mockScanFromAPIScanID = sid

		// Simulate a scan result being stored
		// Ensure options.Scan is initialized if it's nil
		if options.Scan == nil {
			options.Scan = make(map[string]model.Scan)
		}
		currentScan := options.Scan[sid] // GetScan과 동일한 방식으로 스캔 가져오기
		currentScan.URL = url
		currentScan.Results = []model.PoC{ // PoC 사용
			{
				Type:    "test-vuln",
				Param:   "q",
				Payload: "<script>alert(1)</script>",
			},
		}
		options.Scan[sid] = currentScan // 맵에 다시 저장
		// serverScanFromAPI는 반환 값이 없습니다.
	}

	utilsGenerateRandomToken = func(s string) string {
		return "test-scan-id-for-" + s
	}

	exitVal := m.Run()

	serverScanFromAPI = originalServerScanFromAPI // Restore original
	utilsGenerateRandomToken = originalUtilsGenerateRandomToken // Restore original
	os.Exit(exitVal)
}

func runMCPServerWithMockStdio(t *testing.T, options model.Options, inputJSON string) (string, error) {
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	r, w, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("os.Pipe error: %w", err)
	}
	os.Stdin = r

	rout, wout, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("os.Pipe error for stdout: %w", err)
	}
	os.Stdout = wout

	// Write input to the pipe in a goroutine
	go func() {
		defer w.Close()
		_, writeErr := w.Write([]byte(inputJSON + "\n")) // MCP expects newline-terminated JSON
		if writeErr != nil {
			// This error might not be catchable by the main test goroutine easily
			// Consider a channel to report errors from here if necessary.
			t.Logf("Error writing to stdin pipe: %v", writeErr)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		// RunMCPServer is blocking, so it needs its own goroutine
		// It will exit when stdin is closed or an error occurs.
		// The current MCP server `ServeStdio` might not exit cleanly on just Stdin close
		// if it's waiting for more input. The mock MCP server might need a way to be signalled to stop.
		// For this test, we rely on it processing the single input and then potentially hanging or erroring.
		// A timeout on reading stdout might be necessary.
		RunMCPServer(options)
	}()

	// Close the write end of stdout after RunMCPServer finishes or times out
	// This signals to the ReadAll that there's no more output.
	// However, RunMCPServer might block indefinitely.
	// A more robust solution would involve context cancellation for the server.

	var outputBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, readErr := io.Copy(&outputBuf, rout)
		if readErr != nil && readErr != io.EOF {
			t.Logf("Error reading from stdout pipe: %v", readErr)
		}
		close(done)
	}()

	// Wait for RunMCPServer to process the input and produce output.
	// This is tricky because ServeStdio blocks. We need a way to know it's "done"
	// or to make it process just one request for testing.
	// Assuming MCP server processes one request then waits for more.
	// We give it a short time to process.

	// Wait for the server goroutine to complete or timeout
	serverDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(serverDone)
	}()

	select {
	case <-serverDone:
		// Server finished, likely due to input pipe closing
	case <-time.After(2 * time.Second): // Timeout for server processing
		t.Log("RunMCPServer timed out or did not exit as expected")
		// Attempt to close stdin to unblock the server, though it might be too late
		r.Close() // This should cause ServeStdio to eventually exit or error out
	}

	wout.Close() // Close stdout write pipe to unblock io.Copy
	<-done       // Wait for io.Copy to finish

	return outputBuf.String(), serverErr
}

func TestRunMCPServer_ScanTool(t *testing.T) {
	mockScanFromAPICalled = false // Reset mock flag

	options := model.Options{Debug: true, Concurrence: 10, Delay: 100, Mining: true, FindingDOM: true, Scan: make(map[string]model.Scan)}
	// Construct MCP CallToolRequest JSON
	callToolRequest := mcp.CallToolRequest{
		ToolName: "scan_with_dalfox", // CallToolRequestFields의 필드
		Params: mcp.CallToolParams{ // CallToolParams 사용
			Arguments: map[string]any{
				"url":    "http://test.com/vuln?p=1",
				"method": "POST",
					"headers": "X-Custom-Header:value1|X-Another:value2",
					"cookie": "sessionid=12345",
					"data":   "param1=val1&param2=val2",
					"follow-redirects": true,
					"proxy": "http://localhost:8080",
					"worker": float64(50), // MCP sends numbers as float64
					"delay":  float64(200),
					"deep-domxss": true,
					"skip-discovery": false,
					"skip-mining-all": false,
					"skip-mining-dict": false,
					"skip-mining-dom": false,
					"output-request": true,
					"output-response": true,
				}, // Arguments 맵 닫힘
			}, // Params 구조체 닫힘
		}, // CallToolRequest 구조체 닫힘
	}
	inputBytes, _ := json.Marshal(callToolRequest)
	inputJSON := string(inputBytes)

	output, err := runMCPServerWithMockStdio(t, options, inputJSON)
	assert.NoError(t, err, "runMCPServerWithMockStdio should not produce an immediate error")

	t.Logf("MCP Server Output:\n%s", output)

	// Parse the output (should be MCP CallToolResult)
	// MCP server will output multiple JSON objects if logging is enabled.
	// We need to find the CallToolResult.
	var callToolResult mcp.CallToolResult
	foundResult := false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			err = json.Unmarshal([]byte(line), &callToolResult)
			assert.NoError(t, err, "Failed to unmarshal CallToolResult")
			foundResult = true
			break
		}
	}
	assert.True(t, foundResult, "CallToolResult not found in output")

	expectedScanID := "test-scan-id-for-http://test.com/vuln?p=1"
	expectedResultText := fmt.Sprintf("Scan started with ID: %s. The scan is running in the background.", expectedScanID)
	if len(callToolResult.Content) > 0 {
		assert.Equal(t, "text", callToolResult.Content[0].Type)
		assert.Equal(t, expectedResultText, callToolResult.Content[0].Text)
	} else {
		assert.Fail(t, "callToolResult.Content is empty")
	}

	// Wait a bit for the goroutine in the handler to execute ScanFromAPI
	time.Sleep(100 * time.Millisecond)

	assert.True(t, mockScanFromAPICalled, "ScanFromAPI should have been called")
	assert.Equal(t, "http://test.com/vuln?p=1", mockScanFromAPIUrl)
	assert.Equal(t, expectedScanID, mockScanFromAPIScanID)

	// Verify options passed to ScanFromAPI
	assert.Equal(t, "POST", mockScanFromAPIOptions.Method)
	assert.ElementsMatch(t, []string{"X-Custom-Header:value1", "X-Another:value2"}, mockScanFromAPIOptions.Header)
	assert.Equal(t, "sessionid=12345", mockScanFromAPIOptions.Cookie)
	assert.Equal(t, "param1=val1&param2=val2", mockScanFromAPIOptions.Data)
	assert.True(t, mockScanFromAPIOptions.FollowRedirect)
	assert.Equal(t, "http://localhost:8080", mockScanFromAPIOptions.ProxyAddress)
	assert.Equal(t, 50, mockScanFromAPIOptions.Concurrence) // Note: MCP sends numbers as float64, should be converted to int
	assert.Equal(t, 200, mockScanFromAPIOptions.Delay)
	assert.True(t, mockScanFromAPIOptions.UseDeepDXSS)
	assert.False(t, mockScanFromAPIOptions.SkipDiscovery)
	// Skip-mining-all, dict, dom default to false in model.Options, so if not set, they remain false.
	// The test sets them to false, so they should be false.
	assert.True(t, mockScanFromAPIOptions.Mining) // skip-mining-all=false -> Mining=true
	assert.True(t, mockScanFromAPIOptions.FindingDOM) // skip-mining-all=false -> FindingDOM=true
	assert.True(t, mockScanFromAPIOptions.OutputRequest)
	assert.True(t, mockScanFromAPIOptions.OutputResponse)


	// Test skip-mining-all
	mockScanFromAPICalled = false
	callToolRequest.Params.Arguments.(map[string]any)["skip-mining-all"] = true
	callToolRequest.Params.Arguments.(map[string]any)["url"] = "http://test.com/skipall"
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	_, _ = runMCPServerWithMockStdio(t, options, inputJSON)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, mockScanFromAPICalled, "ScanFromAPI should have been called for skip-mining-all")
	assert.False(t, mockScanFromAPIOptions.Mining, "Mining should be false when skip-mining-all is true")
	assert.False(t, mockScanFromAPIOptions.FindingDOM, "FindingDOM should be false when skip-mining-all is true")

	// Test skip-mining-dict
	mockScanFromAPICalled = false
	callToolRequest.Params.Arguments.(map[string]any)["skip-mining-all"] = false // reset
	callToolRequest.Params.Arguments.(map[string]any)["skip-mining-dict"] = true
	callToolRequest.Params.Arguments.(map[string]any)["url"] = "http://test.com/skipdict"
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	_, _ = runMCPServerWithMockStdio(t, options, inputJSON)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, mockScanFromAPICalled, "ScanFromAPI should have been called for skip-mining-dict")
	assert.False(t, mockScanFromAPIOptions.Mining, "Mining should be false when skip-mining-dict is true")
	assert.True(t, mockScanFromAPIOptions.FindingDOM, "FindingDOM should remain true when skip-mining-dict is true and skip-mining-all is false")


	// Test skip-mining-dom
	mockScanFromAPICalled = false
	callToolRequest.Params.Arguments.(map[string]any)["skip-mining-dict"] = false // reset
	callToolRequest.Params.Arguments.(map[string]any)["skip-mining-dom"] = true
	callToolRequest.Params.Arguments.(map[string]any)["url"] = "http://test.com/skipdom"
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	_, _ = runMCPServerWithMockStdio(t, options, inputJSON)
	time.Sleep(50 * time.Millisecond)
	assert.True(t, mockScanFromAPICalled, "ScanFromAPI should have been called for skip-mining-dom")
	assert.True(t, mockScanFromAPIOptions.Mining, "Mining should remain true when skip-mining-dom is true and skip-mining-all is false")
	assert.False(t, mockScanFromAPIOptions.FindingDOM, "FindingDOM should be false when skip-mining-dom is true")

	// Test URL is required
	mockScanFromAPICalled = false
	callToolRequest.Params.Arguments.(map[string]any)["url"] = ""
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	output, _ = runMCPServerWithMockStdio(t, options, inputJSON)
	time.Sleep(50 * time.Millisecond)
	assert.False(t, mockScanFromAPICalled, "ScanFromAPI should NOT be called when URL is empty")
	// Check for error message in output
	foundErrorResult := false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			var errResult mcp.CallToolResult
			json.Unmarshal([]byte(line), &errResult)
			if errResult.Error != nil && strings.Contains(errResult.Error.Message, "URL is required") {
				foundErrorResult = true
				break
			}
		}
	}
	assert.True(t, foundErrorResult, "Expected error message for missing URL not found in output")

}

func TestRunMCPServer_GetResultsTool(t *testing.T) {
	options := model.Options{Debug: true, Scan: make(map[string]model.Scan)}
	scanID := "test-scan-id-for-http://results.test.com"

	// Simulate a completed scan
	sc := model.Scan{
		URL: "http://results.test.com",
		// Results is a slice of PoC in model.Scan
		Results: []model.PoC{
			{
				Type:            "vulnerable",
				InjectType:      "query",
				PoCType:         "alert",
				Method:          "GET",
				Data:            "",
				Param:           "q",
				Payload:         "<script>alert(1)</script>",
				Evidence:        "reflected payload",
				CWE:             "CWE-79",
				Severity:        "High",
				MessageID:       123,
				MessageStr:      "Found XSS",
				RawHTTPRequest:  "GET / HTTP/1.1...",
				RawHTTPResponse: "HTTP/1.1 200 OK...",
			},
		},
		// Options field is not in model.Scan, it's part of the overall server's options
	}
	options.Scan[scanID] = sc // Store in the options map directly

	// Test case: Valid scan ID with results
	callToolRequest := mcp.CallToolRequest{
		ToolName: "get_results_dalfox",
		Params: mcp.CallToolParams{
			Arguments: map[string]any{
				"scan_id": scanID,
			},
			},
		},
	}
	inputBytes, _ := json.Marshal(callToolRequest)
	inputJSON := string(inputBytes)

	output, err := runMCPServerWithMockStdio(t, options, inputJSON)
	assert.NoError(t, err)

	var callToolResult mcp.CallToolResult
	foundResult := false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			json.Unmarshal([]byte(line), &callToolResult)
			foundResult = true
			break
		}
	}
	assert.True(t, foundResult, "CallToolResult not found for get_results_dalfox (valid id)")
	if len(callToolResult.Content) > 0 {
		assert.Equal(t, "text", callToolResult.Content[0].Type)
		assert.Contains(t, callToolResult.Content[0].Text, "Scan results for http://results.test.com")
		assert.Contains(t, callToolResult.Content[0].Text, `"type": "vulnerable"`)
		assert.Contains(t, callToolResult.Content[0].Text, `"param": "q"`)
		assert.Contains(t, callToolResult.Content[0].Text, `"payload": "<script>alert(1)</script>"`)
	} else {
		assert.Fail(t, "callToolResult.Content is empty for valid scan ID")
	}

	// Test case: Scan still in progress (URL is empty in our mock setup for "in progress")
	inProgressScanID := "test-scan-id-for-http://inprogress.test.com"
	// Store an empty scan object to simulate "in progress" where GetScan initializes it but URL isn't set yet
	// (or more accurately, if URL is empty, it's considered in progress by the results tool)
	options.Scan[inProgressScanID] = model.Scan{URL: ""} // Options field is not part of model.Scan

	callToolRequest.Params.Arguments.(map[string]any)["scan_id"] = inProgressScanID
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	output, err = runMCPServerWithMockStdio(t, options, inputJSON)
	assert.NoError(t, err)

	foundResult = false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			json.Unmarshal([]byte(line), &callToolResult)
			foundResult = true
			break
		}
	}
	assert.True(t, foundResult, "CallToolResult not found for get_results_dalfox (in progress)")
	if len(callToolResult.Content) > 0 {
		assert.Equal(t, "text", callToolResult.Content[0].Type)
		assert.Equal(t, "Scan is still in progress. Please check again later.", callToolResult.Content[0].Text)
	} else {
		assert.Fail(t, "callToolResult.Content is empty for in progress scan")
	}

	// Test case: Invalid scan ID
	callToolRequest.Params.Arguments.(map[string]any)["scan_id"] = "invalid-scan-id"
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	output, err = runMCPServerWithMockStdio(t, options, inputJSON)
	assert.NoError(t, err)

	foundResult = false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			json.Unmarshal([]byte(line), &callToolResult)
			foundResult = true
			break
		}
	}
	assert.True(t, foundResult, "CallToolResult not found for get_results_dalfox (invalid id)")
	if len(callToolResult.Content) > 0 {
		assert.Equal(t, "text", callToolResult.Content[0].Type)
		// When scan is not found (invalid ID), GetScan returns an empty Scan struct.
		// The results tool then treats it as "in progress" because scan.URL will be empty.
		assert.Equal(t, "Scan is still in progress. Please check again later.", callToolResult.Content[0].Text)
	} else {
		assert.Fail(t, "callToolResult.Content is empty for invalid scan ID")
	}

	// Test case: Scan ID is required
	callToolRequest.Params.Arguments.(map[string]any)["scan_id"] = ""
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	output, _ = runMCPServerWithMockStdio(t, options, inputJSON)

	foundErrorResult := false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			var errResult mcp.CallToolResult
			json.Unmarshal([]byte(line), &errResult)
			if errResult.Error != nil && strings.Contains(errResult.Error.Message, "scan_id is required") {
				foundErrorResult = true
				break
			}
		}
	}
	assert.True(t, foundErrorResult, "Expected error message for missing scan_id not found in output")

	// Test case: No vulnerabilities found
	noVulnScanID := "test-scan-id-for-http://novuln.test.com"
	options.Scan[noVulnScanID] = model.Scan{URL: "http://novuln.test.com", Results: []model.PoC{}} // Empty PoC slice
	callToolRequest.Params.Arguments.(map[string]any)["scan_id"] = noVulnScanID
	inputBytes, _ = json.Marshal(callToolRequest)
	inputJSON = string(inputBytes)
	output, err = runMCPServerWithMockStdio(t, options, inputJSON)
	assert.NoError(t, err)

	foundResult = false
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.Contains(line, `"type":"call_tool_result"`) {
			json.Unmarshal([]byte(line), &callToolResult)
			foundResult = true
			break
		}
	}
	assert.True(t, foundResult, "CallToolResult not found for get_results_dalfox (no vuln)")
	if len(callToolResult.Content) > 0 {
		assert.Equal(t, "text", callToolResult.Content[0].Type)
		assert.Contains(t, callToolResult.Content[0].Text, "Scan results for http://novuln.test.com")
		assert.Contains(t, callToolResult.Content[0].Text, "No vulnerabilities found.")
	} else {
		assert.Fail(t, "callToolResult.Content is empty for no vuln scan")
	}
}

// Context and request for direct handler testing if needed, though MCP server tests via stdio are more integrated.
func newMockCallToolRequest(toolName string, args map[string]any) (context.Context, mcp.CallToolRequest) {
	return context.Background(), mcp.CallToolRequest{
		ToolName: toolName, // CallToolRequestFields의 필드
		Params: mcp.CallToolParams{ // CallToolParams 사용
			Arguments: args,
		},
		},
	}
}
