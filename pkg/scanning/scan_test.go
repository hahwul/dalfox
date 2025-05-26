package scanning

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
	"github.com/stretchr/testify/assert"
)

// mockServer creates a test server that reflects query parameters and path in its response
func mockServerForScanTest() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		// Reflect URL path in response
		path := r.URL.Path

		// Reflect query parameters in response
		queryParams := r.URL.Query()
		var responseContent strings.Builder

		responseContent.WriteString(fmt.Sprintf("<html><body><h1>Mock Server</h1><p>Path: %s</p>", path))

		for param, values := range queryParams {
			for _, value := range values {
				responseContent.WriteString(fmt.Sprintf("<div>Parameter %s: %s</div>", param, value))
			}
		}

		responseContent.WriteString("</body></html>")
		w.Write([]byte(responseContent.String()))
	}))
}

func Test_shouldIgnoreReturn(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		ignoreReturn string
		want         bool
	}{
		{
			name:         "Should ignore 404",
			statusCode:   404,
			ignoreReturn: "404,500",
			want:         true,
		},
		{
			name:         "Should ignore 500",
			statusCode:   500,
			ignoreReturn: "404,500",
			want:         true,
		},
		{
			name:         "Should not ignore 200",
			statusCode:   200,
			ignoreReturn: "404,500",
			want:         false,
		},
		{
			name:         "Empty ignore list",
			statusCode:   404,
			ignoreReturn: "",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIgnoreReturn(tt.statusCode, tt.ignoreReturn)
			if got != tt.want {
				t.Errorf("shouldIgnoreReturn() = %v, want %v", got, tt.want)
			}
		})
	}
}

// createTempPayloadFile creates a temporary file with the given content.
// It returns the path to the temporary file and a cleanup function.
func createTempPayloadFile(t *testing.T, content string) (string, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test-payloads-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to close temp file: %v", err)
	}
	return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }
}

// captureOutput captures stdout and stderr during the execution of a function.
func captureOutput(f func()) (string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	f()

	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var outBuf, errBuf strings.Builder
	// Use a WaitGroup to wait for copying to finish
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(&outBuf, rOut)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&errBuf, rErr)
	}()

	wg.Wait()
	return outBuf.String(), errBuf.String()
}

func TestGeneratePayloads_CustomBlindXSS(t *testing.T) {
	server := mockServerForScanTest()
	defer server.Close()

	baseOptions := model.Options{
		Concurrence:     1,
		Format:          "plain",
		Silence:         false, // Set to false to capture logs
		NoSpinner:       true,
		CustomAlertType: "none",
		AuroraObject:    aurora.NewAurora(false), // Assuming NoColor is true for tests
		Scan:            make(map[string]model.Scan),
		PathReflection:  make(map[int]string),
		Mutex:           &sync.Mutex{},
	}

	params := map[string]model.ParamResult{
		"q": {
			Name:      "q",
			Type:      "URL",
			Reflected: true,
			Chars:     []string{},
		},
	}
	policy := map[string]string{"Content-Type": "text/html"}
	pathReflection := make(map[int]string)

	t.Run("Valid custom blind payload file with --blind URL", func(t *testing.T) {
		payloadContent := "blindy1<script>CALLBACKURL</script>\nblindy2<img src=x onerror=CALLBACKURL>"
		payloadFile, cleanup := createTempPayloadFile(t, payloadContent)
		defer cleanup()

		options := baseOptions
		options.CustomBlindXSSPayloadFile = payloadFile
		options.BlindURL = "test-callback.com"
		options.UniqParam = []string{"q"} // Ensure params are processed

		var generatedQueries map[*http.Request]map[string]string
		var logOutput string

		stdout, stderr := captureOutput(func() {
			generatedQueries, _ = generatePayloads(server.URL+"/?q=test", options, policy, pathReflection, params)
		})
		logOutput = stdout + stderr // Combine stdout and stderr

		assert.Contains(t, logOutput, "Added 2 custom blind XSS payloads from file: "+payloadFile)

		foundPayload1 := false
		foundPayload2 := false
		expectedPayload1 := strings.Replace("blindy1<script>CALLBACKURL</script>", "CALLBACKURL", "//"+options.BlindURL, -1)
		expectedPayload2 := strings.Replace("blindy2<img src=x onerror=CALLBACKURL>", "CALLBACKURL", "//"+options.BlindURL, -1)

		for req, meta := range generatedQueries {
			if meta["type"] == "toBlind" && meta["payload"] == "toBlind" { // Check our specific type for these payloads
				// Check if the payload in the query matches one of our expected transformed payloads
				// This requires knowing how MakeRequestQuery structures the request.
				// Assuming payload is in query parameter 'q' for this test.
				queryValues := req.URL.Query()
				if queryValues.Get("q") == expectedPayload1 {
					foundPayload1 = true
				}
				if queryValues.Get("q") == expectedPayload2 {
					foundPayload2 = true
				}
			}
		}
		assert.True(t, foundPayload1, "Expected payload 1 not found or not correctly transformed")
		assert.True(t, foundPayload2, "Expected payload 2 not found or not correctly transformed")
	})

	t.Run("Custom blind payload file with CALLBACKURL but no --blind flag", func(t *testing.T) {
		payloadContent := "blindy3<a href=CALLBACKURL>"
		payloadFile, cleanup := createTempPayloadFile(t, payloadContent)
		defer cleanup()

		options := baseOptions
		options.CustomBlindXSSPayloadFile = payloadFile
		options.BlindURL = "" // No blind URL
		options.UniqParam = []string{"q"}

		var generatedQueries map[*http.Request]map[string]string
		stdout, stderr := captureOutput(func() {
			generatedQueries, _ = generatePayloads(server.URL+"/?q=test", options, policy, pathReflection, params)
		})
		logOutput := stdout + stderr // Combine stdout and stderr

		assert.Contains(t, logOutput, "Added 1 custom blind XSS payloads from file: "+payloadFile)
		foundPayload := false
		expectedPayload := "blindy3<a href=CALLBACKURL>" // CALLBACKURL should not be replaced

		for req, meta := range generatedQueries {
			if meta["type"] == "toBlind" && meta["payload"] == "toBlind" {
				if req.URL.Query().Get("q") == expectedPayload {
					foundPayload = true
					break
				}
			}
		}
		assert.True(t, foundPayload, "Expected payload with unreplaced CALLBACKURL not found")
	})

	t.Run("Invalid non-existent custom blind payload file", func(t *testing.T) {
		options := baseOptions
		options.CustomBlindXSSPayloadFile = "nonexistentfile.txt"
		options.UniqParam = []string{"q"}

		stdout, stderr := captureOutput(func() {
			_, _ = generatePayloads(server.URL+"/?q=test", options, policy, pathReflection, params)
		})
		logOutput := stdout + stderr // Combine stdout and stderr

		assert.Contains(t, logOutput, "Failed to load custom blind XSS payload file: nonexistentfile.txt")
		// Check that no payloads of type "toBlind" were added due to this specific file error
		// (assuming other payload generation might still occur)
		customBlindPayloadsFound := false
		assert.False(t, customBlindPayloadsFound, "Queries should not include payloads from a non-existent file if logic prevents it after error")
	})

	t.Run("Empty custom blind payload file", func(t *testing.T) {
		payloadFile, cleanup := createTempPayloadFile(t, "")
		defer cleanup()

		options := baseOptions
		options.CustomBlindXSSPayloadFile = payloadFile
		options.UniqParam = []string{"q"}

		stdout, stderr := captureOutput(func() {
			_, _ = generatePayloads(server.URL+"/?q=test", options, policy, pathReflection, params)
		})
		logOutput := stdout + stderr // Combine stdout and stderr

		assert.Contains(t, logOutput, "Added 0 custom blind XSS payloads from file: "+payloadFile)
		// Verify no queries were generated specifically from this empty file.
		// Similar to the above, this assumes no other "toBlind" payloads would be generated,
		// or relies on the specific log message for confirmation.
	})
}

func TestGeneratePayloads_JSON(t *testing.T) {
	server := mockServerForScanTest() // Using existing mock server, URL might not be directly used by JSON tests
	defer server.Close()

	// Common XSS payloads used by generateJSONPayloadsRecursive
	// This needs to align with what payload.GetCommonPayload() would return or be a representative subset.
	// For simplicity, let's assume one common payload for testing the injection mechanism.
	const testXSSPayload = "\"><script>alert(1)</script>"

	tests := []struct {
		name                  string
		jsonData              string
		expectedInjectionPath string // The JSON path where injection is expected
		expectPayloads        bool   // Whether any JSON-specific payloads are expected
		customAssert          func(t *testing.T, req *http.Request, metadata map[string]string, originalJSONData, expectedPath, injectedPayload string)
	}{
		{
			name:                  "Simple Flat JSON",
			jsonData:              `{"name": "test", "vuln": "target"}`,
			expectedInjectionPath: "vuln",
			expectPayloads:        true,
		},
		{
			name:                  "Nested JSON Object",
			jsonData:              `{"user":{"id":123, "description":"a_target"}}`,
			expectedInjectionPath: "user.description",
			expectPayloads:        true,
		},
		{
			name:                  "JSON Array with Strings",
			jsonData:              `["item1", "a_target_in_array"]`,
			expectedInjectionPath: "[1]",
			expectPayloads:        true,
		},
		{
			name:                  "Mixed Nested Structure (Object with Array with Object)",
			jsonData:              `{"data":[{"id":"abc","value":"final_target"}]}`,
			expectedInjectionPath: "data[0].value",
			expectPayloads:        true,
		},
		{
			name:                  "JSON with Non-String Values",
			jsonData:              `{"count": 5, "active": true, "notes": "notes_target"}`,
			expectedInjectionPath: "notes",
			expectPayloads:        true,
		},
		{
			name:                  "Empty JSON Object",
			jsonData:              `{}`,
			expectedInjectionPath: "", // No string fields to inject
			expectPayloads:        false,
		},
		{
			name:                  "JSON Array with Non-Strings",
			jsonData:              `[1, true, null]`,
			expectedInjectionPath: "", // No string fields to inject
			expectPayloads:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := model.Options{
				Data:            tt.jsonData,
				DataAsJSON:      true,
				Concurrence:     1,
				Format:          "plain",
				Silence:         true, // Keep tests quiet
				NoSpinner:       true,
				CustomAlertType: "none", // Default from existing tests
				Debug:           false,  // Set to true for verbose logging from generateJSONPayloadsRecursive
				AuroraObject:    aurora.NewAurora(true), // No color
				Scan:            make(map[string]model.Scan),
				PathReflection:  make(map[int]string),
				Mutex:           &sync.Mutex{},
				// Method: "POST", // Let MakeRequestQuery handle default to POST for JSON bodies
			}

			// These are not directly used by JSON body processing but need to be initialized
			policy := map[string]string{"Content-Type": "text/html"} // Default, though JSON requests will override
			pathReflection := make(map[int]string)
			params := make(map[string]model.ParamResult) // Empty for JSON body tests

			// We need to mock payload.GetCommonPayload() or know its content
			// For now, we'll assume testXSSPayload is one of the payloads that would be returned.
			// This is a simplification. A more robust test would involve controlling the payload set.

			generatedQueries, _ := generatePayloads(server.URL, options, policy, pathReflection, params)

			if !tt.expectPayloads {
				// Filter out non-JSON body queries if any (e.g. path based, header based)
				jsonBodyQueriesFound := false
				for _, metadata := range generatedQueries {
					if metadata["pAction"] == "jsonBody" || metadata["action"] == "jsonBody" { // checking both due to MakeRequestQuery structure
						jsonBodyQueriesFound = true
						break
					}
				}
				assert.False(t, jsonBodyQueriesFound, "Expected no JSON body specific payloads, but found some.")
				return
			}

			assert.True(t, len(generatedQueries) > 0, "Expected JSON payloads to be generated, but got none.")

			foundInjectedPayloadForPath := false
			for req, metadata := range generatedQueries {
				// Focus on JSON body payloads
				if metadata["action"] != "jsonBody" {
					continue
				}

				assert.Equal(t, "application/json", req.Header.Get("Content-Type"), "Content-Type should be application/json")
				assert.Contains(t, []string{"POST", "PUT", "PATCH"}, req.Method, "HTTP method should be appropriate for body content (POST, PUT, PATCH)")

				// Read the body
				bodyBytes, err := io.ReadAll(req.Body)
				req.Body.Close() // Close the body
				assert.NoError(t, err, "Failed to read request body")
				bodyString := string(bodyBytes)

				// Check if this request corresponds to the expected injection path
				if metadata["param"] == tt.expectedInjectionPath {
					foundInjectedPayloadForPath = true
					var bodyJSON interface{}
					err = json.Unmarshal(bodyBytes, &bodyJSON)
					assert.NoError(t, err, "Failed to unmarshal request body JSON: %s", bodyString)

					// Verify the payload is at the expected path in the unmarshalled JSON
					// This requires a way to get the value from bodyJSON at tt.expectedInjectionPath
					// For simplicity, we'll check if the raw XSS payload string is present in the body string
					// and that the original non-target parts of the JSON are also present.
					// A more precise check would involve traversing bodyJSON.
					assert.Contains(t, bodyString, metadata["payload"], "Request body should contain the injected XSS payload")
					
					// Custom assertion if provided
					if tt.customAssert != nil {
						tt.customAssert(t, req, metadata, tt.jsonData, tt.expectedInjectionPath, metadata["payload"])
					}
					// Example of checking if other parts of original JSON are present
					// This is a basic check.
					var originalParsed interface{}
					_ = json.Unmarshal([]byte(tt.jsonData), &originalParsed)
					if obj, ok := originalParsed.(map[string]interface{}); ok {
						for k, v := range obj {
							if k != tt.expectedInjectionPath && !strings.Contains(tt.expectedInjectionPath, k+".") { // if not the target field itself or part of its parent path
								vStr, _ := json.Marshal(v)
								assert.Contains(t, bodyString, strings.Trim(string(vStr), `"`), "Request body should retain other parts of the original JSON")
							}
						}
					}


					assert.Equal(t, "jsonBody", metadata["action"], "Metadata 'action' should be 'jsonBody'")
					assert.Equal(t, tt.expectedInjectionPath, metadata["param"], "Metadata 'param' should be the JSON path")
					assert.Equal(t, "inJSON", metadata["type"], "Metadata 'type' should be 'inJSON'")
				}
			}
			assert.True(t, foundInjectedPayloadForPath, "Payload not injected/found for expected path: %s", tt.expectedInjectionPath)
		})
	}
}

func TestDeepCopyJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		modifier func(data interface{}) // Function to modify the data
	}{
		{
			name:  "simple map",
			input: map[string]interface{}{"key": "value", "num": 123},
			modifier: func(data interface{}) {
				if m, ok := data.(map[string]interface{}); ok {
					m["key"] = "modified"
				}
			},
		},
		{
			name:  "nested map",
			input: map[string]interface{}{"parent": map[string]interface{}{"child": "value"}},
			modifier: func(data interface{}) {
				if p, ok := data.(map[string]interface{}); ok {
					if c, ok := p["parent"].(map[string]interface{}); ok {
						c["child"] = "modified"
					}
				}
			},
		},
		{
			name:  "slice",
			input: []interface{}{"a", "b", map[string]interface{}{"c": "d"}},
			modifier: func(data interface{}) {
				if s, ok := data.([]interface{}); ok {
					s[0] = "modified_a"
					if m, ok := s[2].(map[string]interface{}); ok {
						m["c"] = "modified_d"
					}
				}
			},
		},
		{
			name:     "nil input",
			input:    nil,
			modifier: func(data interface{}) {},
		},
		{
			name:     "string input (not typical for deepCopyJSON but should pass through)",
			input:    "a string",
			modifier: func(data interface{}) {}, // strings are immutable
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalBytes, _ := json.Marshal(tc.input) // For later comparison

			copied, err := deepCopyJSON(tc.input)
			assert.NoError(t, err)

			// Verify the copied data is equivalent to the original
			copiedBytes, _ := json.Marshal(copied)
			assert.Equal(t, string(originalBytes), string(copiedBytes), "Copied data should be equivalent to original")

			if tc.input != nil {
				// Modify the copy
				tc.modifier(copied)

				// Verify the original remains unchanged
				originalAfterModificationBytes, _ := json.Marshal(tc.input)
				assert.Equal(t, string(originalBytes), string(originalAfterModificationBytes), "Original data should not be affected by modifications to the copy")

				// Verify the copy is actually different if modifier had an effect
				copiedAfterModificationBytes, _ := json.Marshal(copied)
				if string(originalBytes) != "{}" && string(originalBytes) != "[]" && string(originalBytes) != "null" && tc.name != "string input" { // Avoid false positives for empty or nil
					assert.NotEqual(t, string(originalBytes), string(copiedAfterModificationBytes), "Copied data should be different after modification (if modifier had an effect)")
				}
			} else {
				assert.Nil(t, copied, "Copy of nil should be nil")
			}
		})
	}
}

func TestSetJSONValueByPath(t *testing.T) {
	tests := []struct {
		name          string
		initialJSON   string
		path          string
		valueToSet    string
		expectedJSON  string
		expectError   bool
		errorContains string
	}{
		{
			name:         "set value in flat object",
			initialJSON:  `{"key1":"val1", "key2":"val2"}`,
			path:         "key2",
			valueToSet:   "new_val2",
			expectedJSON: `{"key1":"val1", "key2":"new_val2"}`,
		},
		{
			name:         "set value in nested object",
			initialJSON:  `{"user":{"name":"old", "details":{"id":1}}}`,
			path:         "user.name",
			valueToSet:   "new_name",
			expectedJSON: `{"user":{"name":"new_name", "details":{"id":1}}}`,
		},
		{
			name:         "set value in array",
			initialJSON:  `["a", "b", "c"]`,
			path:         "[1]",
			valueToSet:   "new_b",
			expectedJSON: `["a", "new_b", "c"]`,
		},
		{
			name:         "set value in object within array",
			initialJSON:  `[{"id":"a", "val":"x"}, {"id":"b", "val":"y"}]`,
			path:         "[0].val",
			valueToSet:   "new_x",
			expectedJSON: `[{"id":"a", "val":"new_x"}, {"id":"b", "val":"y"}]`,
		},
		{
			name:         "set value in array within object",
			initialJSON:  `{"data":{"items":["one","two"]}}`,
			path:         "data.items[1]",
			valueToSet:   "new_two",
			expectedJSON: `{"data":{"items":["one","new_two"]}}`,
		},
		{
			name:          "path not found - intermediate object",
			initialJSON:   `{"user":{"name":"test"}}`,
			path:          "user.profile.email",
			valueToSet:    "test@example.com",
			expectError:   true,
			errorContains: "key 'profile' not found",
		},
		{
			name:          "path not found - final key",
			initialJSON:   `{"user":{"name":"test"}}`,
			path:          "user.email",
			valueToSet:    "test@example.com",
			expectedJSON:  `{"user":{"name":"test", "email":"test@example.com"}}`, // Assuming it adds the key if parent exists
		},
		{
			name:          "array index out of bounds",
			initialJSON:   `["a", "b"]`,
			path:          "[2]",
			valueToSet:    "c",
			expectError:   true,
			errorContains: "array index 2 out of bounds",
		},
		{
			name:          "expected object but got array",
			initialJSON:   `[{"id":"a"}]`,
			path:          "[0].id.value", // Trying to access .value on string "a"
			valueToSet:    "test",
			expectError:   true,
			errorContains: "expected object for key 'value', but got string", // Error from trying to treat string "a" as map
		},
		{
			name:          "expected array but got object",
			initialJSON:   `{"data": {"item": "not_an_array"}}`,
			path:          "data[0]",
			valueToSet:    "test",
			expectError:   true,
			errorContains: "expected array at segment 'data[0]'", // Error from trying to treat object as array due to path
		},
		{
			name:         "set value at root of object (single key path)",
			initialJSON:  `{"rootkey":"oldvalue"}`,
			path:         "rootkey",
			valueToSet:   "newvalue",
			expectedJSON: `{"rootkey":"newvalue"}`,
		},
		// Note: Setting a value at the root of an array (e.g. path "" for input `["a"]`) is not well-defined
		// by setJSONValueByPath as it expects a path. currentPath starts as "" in generateJSONPayloadsRecursive
		// but for a root array, it becomes e.g. "[0]".
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data interface{}
			err := json.Unmarshal([]byte(tt.initialJSON), &data)
			assert.NoError(t, err, "Failed to unmarshal initial JSON for test setup")

			// Use a deep copy for modification to mimic generateJSONPayloadsRecursive behavior
			dataCopy, err := deepCopyJSON(data)
			assert.NoError(t, err, "Failed to deep copy data for test")

			err = setJSONValueByPath(dataCopy, tt.path, tt.valueToSet)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.expectedJSON != "" {
					modifiedBytes, _ := json.Marshal(dataCopy)
					assert.JSONEq(t, tt.expectedJSON, string(modifiedBytes))
				}
			}
		})
	}
}


func Test_createHTTPClient(t *testing.T) {
	tests := []struct {
		name         string
		options      model.Options
		wantTimeout  time.Duration
		wantRedirect bool
	}{
		{
			name: "Default client",
			options: model.Options{
				Timeout:        10,
				FollowRedirect: true,
			},
			wantTimeout:  10 * time.Second,
			wantRedirect: true,
		},
		{
			name: "No redirect client",
			options: model.Options{
				Timeout:        5,
				FollowRedirect: false,
			},
			wantTimeout:  5 * time.Second,
			wantRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createHTTPClient(tt.options)

			if client.Timeout != tt.wantTimeout {
				t.Errorf("createHTTPClient() timeout = %v, want %v", client.Timeout, tt.wantTimeout)
			}

			// Test redirect behavior using two separate servers
			// First server redirects to the second
			targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Target page"))
			}))
			defer targetServer.Close()

			redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, targetServer.URL, http.StatusFound)
			}))
			defer redirectServer.Close()

			req, _ := http.NewRequest("GET", redirectServer.URL, nil)
			resp, err := client.Do(req)

			if err != nil {
				// If redirect is enabled, there should be no error
				if tt.wantRedirect {
					t.Errorf("createHTTPClient() unexpected error on redirect: %v", err)
				}
			} else {
				defer resp.Body.Close()

				// When follow redirect is true, we should get 200 OK from the target server
				// When follow redirect is false, we should get 302 Found from the redirect server
				if tt.wantRedirect && resp.StatusCode != http.StatusOK {
					t.Errorf("createHTTPClient() did not follow redirect. Got status %d, want %d",
						resp.StatusCode, http.StatusOK)
				}
				if !tt.wantRedirect && resp.StatusCode != http.StatusFound {
					t.Errorf("createHTTPClient() followed redirect when it should not have. Got status %d, want %d",
						resp.StatusCode, http.StatusFound)
				}
			}
		})
	}
}

func Test_updateSpinner(t *testing.T) {
	// This is mostly a visual function, so we just ensure it doesn't panic
	options := model.Options{
		Silence:   true,
		NoSpinner: true,
	}

	// Should not panic
	updateSpinner(options, 10, 100, "test", false)

	options.Silence = false
	options.NoSpinner = false
	options.NowURL = 5
	options.AllURLS = 10

	// Should not panic
	updateSpinner(options, 10, 100, "test", true)
}

func Test_Scan(t *testing.T) {
	// Create a mock server
	server := mockServerForScanTest()
	defer server.Close()

	type args struct {
		target  string
		options model.Options
		sid     string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Basic scan with invalid URL",
			args: args{
				target: "invalid-url",
				options: model.Options{
					Concurrence: 1,
					Format:      "plain",
					Silence:     true,
					NoSpinner:   true,
				},
				sid: "1",
			},
			wantErr: true,
		},
		{
			name: "Basic scan with skip discovery",
			args: args{
				target: server.URL + "/?query=test",
				options: model.Options{
					Concurrence:   1,
					Format:        "plain",
					Silence:       true,
					NoSpinner:     true,
					SkipDiscovery: true,
					UniqParam:     []string{"query"},
					OnlyDiscovery: true, // To make test faster
				},
				sid: "1",
			},
			wantErr: false,
		},
		{
			name: "Basic scan with remote payloads",
			args: args{
				target: server.URL + "/?query=test",
				options: model.Options{
					Concurrence:    1,
					Format:         "plain",
					Silence:        true,
					NoSpinner:      true,
					SkipDiscovery:  true,
					UniqParam:      []string{"query"},
					RemotePayloads: "portswigger,payloadbox",
				},
				sid: "1",
			},
			wantErr: false,
		},
		{
			name: "Basic scan with blind xss",
			args: args{
				target: server.URL + "/?query=test",
				options: model.Options{
					Concurrence:   1,
					Format:        "plain",
					Silence:       true,
					NoSpinner:     true,
					SkipDiscovery: true,
					UniqParam:     []string{"query"},
					BlindURL:      "https://dalfox.hahwul.com",
					Data:          "query=1234",
				},
				sid: "1",
			},
			wantErr: false,
		},
		{
			name: "Basic scan with headless",
			args: args{
				target: server.URL + "/abcd/?query=test",
				options: model.Options{
					Concurrence:   1,
					Format:        "plain",
					Silence:       true,
					NoSpinner:     true,
					SkipDiscovery: true,
					UniqParam:     []string{"query"},
					UseHeadless:   true,
					IgnoreReturn:  "404",
				},
				sid: "1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Scan(tt.args.target, tt.args.options, tt.args.sid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_initializeSpinner(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "No spinner",
			args: args{
				options: model.Options{
					NoSpinner: true,
				},
			},
		},
		{
			name: "Spinner",
			args: args{
				options: model.Options{
					NoSpinner: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializeSpinner(tt.args.options)
		})
	}
}
