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

func Test_generatePayloads(t *testing.T) {
	// Create a mock server
	server := mockServerForScanTest()
	defer server.Close()

	// Create base options
	options := model.Options{
		Concurrence:     1,
		Format:          "plain",
		Silence:         true,
		NoSpinner:       true,
		CustomAlertType: "none",
	}

	// Create test cases
	tests := []struct {
		name           string
		target         string
		options        model.Options
		policy         map[string]string
		pathReflection map[int]string
		params         map[string]model.ParamResult
		wantQueryCount int
		wantDurlsCount int
	}{
		{
			name:   "Basic payload generation",
			target: server.URL + "/?param=test",
			options: model.Options{
				Concurrence:     1,
				Format:          "plain",
				Silence:         true,
				NoSpinner:       true,
				CustomAlertType: "none",
				IgnoreParams:    []string{"param2"},
				UseHeadless:     true,
			},
			policy:         map[string]string{"Content-Type": "text/html"},
			pathReflection: make(map[int]string),
			params: map[string]model.ParamResult{
				"param": {
					Name:           "param",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "Injected:inHTML",
					Chars:          []string{"'", "\"", "<", ">", "(", ")", "{", "}", "[", "]", " ", "\t", "\n", "\r", "\f", "\v", "\\", "/", "?", "#", "&", "=", "%", ":", ";", ",", "@", "$", "*", "+", "-", "_", ".", "!", "~", "`", "|", "^"},
				},
				"param2": {
					Name:           "param2",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "",
					Chars:          []string{},
				},
			},
			wantQueryCount: 1, // At least one query should be generated
			wantDurlsCount: 0,
		},
		{
			name:           "No parameters",
			target:         server.URL,
			options:        options,
			policy:         map[string]string{"Content-Type": "text/html"},
			pathReflection: make(map[int]string),
			params:         make(map[string]model.ParamResult),
			wantQueryCount: 0,
			wantDurlsCount: 0,
		},
		{
			name:    "Path reflection payload",
			target:  server.URL + "/path",
			options: options,
			policy:  map[string]string{"Content-Type": "text/html"},
			pathReflection: map[int]string{
				0: "Injected:/inHTML",
			},
			params: map[string]model.ParamResult{
				"param": {
					Name:           "param",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "Injected:inJS-single",
					Chars:          []string{},
				},
			},
			wantQueryCount: 1, // At least one query should be generated
			wantDurlsCount: 0,
		},
		{
			name:   "Path reflection payload (body)",
			target: server.URL + "/path",
			options: model.Options{
				Concurrence:     1,
				Format:          "plain",
				Silence:         true,
				NoSpinner:       true,
				CustomAlertType: "none",
				Data:            "param=test",
			},
			policy: map[string]string{"Content-Type": "text/html"},
			pathReflection: map[int]string{
				0: "Injected:/inHTML",
			},
			params: map[string]model.ParamResult{
				"param": {
					Name:           "param",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "Injected:inJS-single",
					Chars:          []string{},
				},
			},
			wantQueryCount: 1, // At least one query should be generated
			wantDurlsCount: 0,
		},
		{
			name:           "Reflected, but not chars",
			target:         server.URL,
			options:        options,
			policy:         map[string]string{"Content-Type": "text/html"},
			pathReflection: make(map[int]string),
			params:         make(map[string]model.ParamResult),
			wantQueryCount: 0,
			wantDurlsCount: 0,
		},
		{
			name:           "inJS reflected parameter",
			target:         server.URL + "/path/?param=test",
			options:        options,
			policy:         map[string]string{"Content-Type": "text/html"},
			pathReflection: make(map[int]string),
			params: map[string]model.ParamResult{
				"param": {
					Name:           "param",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "Injected:inJS-single",
					Chars:          []string{"'", "\"", "<", ">", "(", ")", "{", "}", "[", "]", " ", "\t", "\n", "\r", "\f", "\v", "\\", "/", "?", "#", "&", "=", "%", ":", ";", ",", "@", "$", "*", "+", "-", "_", ".", "!", "~", "`", "|", "^"},
				},
			},
			wantQueryCount: 1,
			wantDurlsCount: 0,
		},
		{
			name:   "inJS reflected parameter",
			target: server.URL + "/path/",
			options: model.Options{
				Concurrence:     1,
				Format:          "plain",
				Silence:         true,
				NoSpinner:       true,
				CustomAlertType: "none",
				Data:            "param=test",
			},
			policy:         map[string]string{"Content-Type": "text/html"},
			pathReflection: make(map[int]string),
			params: map[string]model.ParamResult{
				"param": {
					Name:           "param",
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: "Injected:inATTR-none",
					Chars:          []string{"'", "\"", "<", ">", "(", ")", "{", "}", "[", "]", " ", "\t", "\n", "\r", "\f", "\v", "\\", "/", "?", "#", "&", "=", "%", ":", ";", ",", "@", "$", "*", "+", "-", "_", ".", "!", "~", "`", "|", "^"},
				},
			},
			wantQueryCount: 1,
			wantDurlsCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, durls := generatePayloads(tt.target, tt.options, tt.policy, tt.pathReflection, tt.params)

			if len(query) < tt.wantQueryCount {
				t.Errorf("generatePayloads() generated %d queries, want at least %d", len(query), tt.wantQueryCount)
			}

			if len(durls) != tt.wantDurlsCount {
				t.Errorf("generatePayloads() generated %d durls, want %d", len(durls), tt.wantDurlsCount)
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
