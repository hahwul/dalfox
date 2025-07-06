package payload

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetPortswiggerPayloadWithSize(t *testing.T) {
	// This test will make actual HTTP requests if not mocked.
	// For robust testing, consider mocking http.Get.
	// However, the function itself calls GetPortswiggerPayload which calls getAssetHahwul.
	// We will test getAssetHahwul with a mock server.

	// Basic check, assuming external service is available or it returns empty on failure.
	payloads, size := GetPortswiggerPayloadWithSize()
	if size < 0 { // Size can be 0 if the external call fails or returns no payloads
		t.Errorf("Expected non-negative size, got %d", size)
	}
	if len(payloads) != size {
		t.Errorf("Payload count %d does not match reported size %d", len(payloads), size)
	}
}

func TestGetPayloadBoxPayloadWithSize(t *testing.T) {
	// Similar to TestGetPortswiggerPayloadWithSize, relies on external service or graceful failure.
	payloads, size := GetPayloadBoxPayloadWithSize()
	if size < 0 {
		t.Errorf("Expected non-negative size, got %d", size)
	}
	if len(payloads) != size {
		t.Errorf("Payload count %d does not match reported size %d", len(payloads), size)
	}
}

func Test_getAssetHahwul(t *testing.T) {
	validAssetJSON := `{"line":"2","size":"10 bytes"}`
	validPayloadData := "payload1\npayload2"

	emptyPayloadData := ""

	tests := []struct {
		name                string
		apiContent          string
		dataContent         string
		mockError           bool // Simulate http.Get error
		expectedPayloads    []string
		expectedLine        string
		expectedSize        string
		expectErrorResponse bool // True if we expect empty results due to simulated errors
	}{
		{
			name:             "successful fetch",
			apiContent:       validAssetJSON,
			dataContent:      validPayloadData,
			expectedPayloads: []string{"payload1", "payload2"},
			expectedLine:     "2",
			expectedSize:     "10 bytes",
		},
		{
			name:                "API endpoint HTTP error",
			mockError:           true, // Simulate error for the API call
			expectErrorResponse: true,
		},
		{
			name:                "Data endpoint HTTP error",
			apiContent:          validAssetJSON, // API call succeeds
			mockError:           true,           // Simulate error for the data call
			expectErrorResponse: true,
		},
		{
			name:             "empty payload data",
			apiContent:       validAssetJSON,
			dataContent:      emptyPayloadData,
			expectedPayloads: []string{}, // splitLines on "" might give {""} or {}, depends on impl.
			// current splitLines gives empty slice for empty string.
			expectedLine: "2",
			expectedSize: "10 bytes",
		},
		{
			name:             "malformed JSON (unmarshal error)",
			apiContent:       `{"line":, "size": "some size"}`, // Invalid JSON due to comma after line:
			dataContent:      validPayloadData,
			expectedPayloads: []string{"payload1", "payload2"}, // Payloads data should still be fetched
			expectedLine:     "",                               // Default due to unmarshal error of apiContent
			expectedSize:     "",                               // Default due to unmarshal error of apiContent
		},
	}

	// originalHTTPGet := httpGet // No longer needed
	// defer func() { httpGet = originalHTTPGet }()

	originalBaseURL := assetHahwulBaseURL                   // Store original base URL
	defer func() { assetHahwulBaseURL = originalBaseURL }() // Restore it after all tests in this function

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var currentApiEP, currentDataEP string
			switch tt.name {
			case "successful fetch", "empty payload data", "malformed JSON (unmarshal error)":
				currentApiEP = "test_api.json"
				currentDataEP = "test_data.txt"
			case "API endpoint HTTP error":
				currentApiEP = "api_error_trigger.json"
				currentDataEP = "some_data_for_api_error_case.txt"
			case "Data endpoint HTTP error":
				currentApiEP = "good_api_for_data_error_case.json"
				currentDataEP = "data_error_trigger.txt"
			default:
				t.Fatalf("Test case %s has unhandled endpoint configuration", tt.name)
			}

			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Mock server in Test_getAssetHahwul for '%s' received request for: %s", tt.name, r.URL.Path)

				// API endpoint error simulation
				if tt.name == "API endpoint HTTP error" && strings.HasSuffix(r.URL.Path, currentApiEP) {
					t.Logf("Mock server simulating API error for %s", r.URL.Path)
					http.Error(w, "Simulated API Down", http.StatusInternalServerError)
					return
				}
				// Data endpoint error simulation
				if tt.name == "Data endpoint HTTP error" && strings.HasSuffix(r.URL.Path, currentDataEP) {
					t.Logf("Mock server simulating Data error for %s", r.URL.Path)
					http.Error(w, "Simulated Data Down", http.StatusInternalServerError)
					return
				}

				// Normal responses
				if strings.HasSuffix(r.URL.Path, ".json") {
					w.Header().Set("Content-Type", "application/json")
					if _, err := w.Write([]byte(tt.apiContent)); err != nil {
						t.Logf("Error writing JSON response in mock server: %v", err)
						http.Error(w, "failed to write json", http.StatusInternalServerError)
					}
				} else if strings.HasSuffix(r.URL.Path, ".txt") {
					if _, err := w.Write([]byte(tt.dataContent)); err != nil {
						t.Logf("Error writing TXT response in mock server: %v", err)
						http.Error(w, "failed to write txt", http.StatusInternalServerError)
					}
				} else {
					t.Logf("Mock server received unexpected path: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer mockServer.Close()

			assetHahwulBaseURL = mockServer.URL // Override base URL to point to mock server

			payloads, line, size := getAssetHahwul(currentApiEP, currentDataEP)

			if tt.expectErrorResponse {
				if len(payloads) != 0 || line != "" || size != "" {
					t.Errorf("getAssetHahwul() with simulated error = (%v, %q, %q), want empty results", payloads, line, size)
				}
				return
			}

			if !equalSlices(payloads, tt.expectedPayloads) {
				t.Errorf("getAssetHahwul() payloads = %v, want %v", payloads, tt.expectedPayloads)
			}
			if line != tt.expectedLine {
				t.Errorf("getAssetHahwul() line = %q, want %q", line, tt.expectedLine)
			}
			if size != tt.expectedSize {
				t.Errorf("getAssetHahwul() size = %q, want %q", size, tt.expectedSize)
			}
		})
	}
}

// var httpGet = http.Get // No longer needed

func TestGetPortswiggerPayload(t *testing.T) {
	assetJSON := `{"line":"10","size":"100kb"}`
	payloadData := "ps_payload1\nps_payload2"
	expectedPayloads := []string{"ps_payload1", "ps_payload2"}

	originalBaseURL := assetHahwulBaseURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "xss-portswigger.json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, assetJSON)
		} else if strings.HasSuffix(r.URL.Path, "xss-portswigger.txt") {
			fmt.Fprintln(w, payloadData)
		} else {
			http.NotFound(w, r)
		}
	}))
	assetHahwulBaseURL = mockServer.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		mockServer.Close()
	}()

	payloads, line, size := GetPortswiggerPayload()

	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("GetPortswiggerPayload() payloads = %v, want %v", payloads, expectedPayloads)
	}
	if line != "10" {
		t.Errorf("GetPortswiggerPayload() line = %s; want 10", line)
	}
	if size != "100kb" {
		t.Errorf("GetPortswiggerPayload() size = %s; want 100kb", size)
	}
}

func TestGetPayloadBoxPayload(t *testing.T) {
	assetJSON := `{"line":"5","size":"50kb"}`
	payloadData := "pb_payload1\npb_payload2"
	expectedPayloads := []string{"pb_payload1", "pb_payload2"}

	originalBaseURL := assetHahwulBaseURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "xss-payloadbox.json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, assetJSON)
		} else if strings.HasSuffix(r.URL.Path, "xss-payloadbox.txt") {
			fmt.Fprintln(w, payloadData)
		} else {
			http.NotFound(w, r)
		}
	}))
	assetHahwulBaseURL = mockServer.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		mockServer.Close()
	}()

	payloads, line, size := GetPayloadBoxPayload()

	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("GetPayloadBoxPayload() payloads = %v, want %v", payloads, expectedPayloads)
	}
	if line != "5" {
		t.Errorf("GetPayloadBoxPayload() line = %s; want 5", line)
	}
	if size != "50kb" {
		t.Errorf("GetPayloadBoxPayload() size = %s; want 50kb", size)
	}
}

func TestGetBurpWordlist(t *testing.T) {
	assetJSON := `{"line":"100","size":"1MB"}`
	payloadData := "burp_param1\nburp_param2"
	expectedPayloads := []string{"burp_param1", "burp_param2"}

	originalBaseURL := assetHahwulBaseURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "wl-params.json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, assetJSON)
		} else if strings.HasSuffix(r.URL.Path, "wl-params.txt") {
			fmt.Fprintln(w, payloadData)
		} else {
			http.NotFound(w, r)
		}
	}))
	assetHahwulBaseURL = mockServer.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		mockServer.Close()
	}()

	payloads, line, size := GetBurpWordlist()
	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("GetBurpWordlist() payloads = %v, want %v", payloads, expectedPayloads)
	}
	if line != "100" {
		t.Errorf("GetBurpWordlist() line = %s; want 100", line)
	}
	if size != "1MB" {
		t.Errorf("GetBurpWordlist() size = %s; want 1MB", size)
	}
}

func TestGetAssetnoteWordlist(t *testing.T) {
	assetJSON := `{"line":"200","size":"2MB"}`
	payloadData := "assetnote_param1\nassetnote_param2"
	expectedPayloads := []string{"assetnote_param1", "assetnote_param2"}

	originalBaseURL := assetHahwulBaseURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "wl-assetnote-params.json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, assetJSON)
		} else if strings.HasSuffix(r.URL.Path, "wl-assetnote-params.txt") {
			fmt.Fprintln(w, payloadData)
		} else {
			http.NotFound(w, r)
		}
	}))
	assetHahwulBaseURL = mockServer.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		mockServer.Close()
	}()

	payloads, line, size := GetAssetnoteWordlist()

	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("GetAssetnoteWordlist() payloads = %v, want %v", payloads, expectedPayloads)
	}
	if line != "200" {
		t.Errorf("GetAssetnoteWordlist() line = %s; want 200", line)
	}
	if size != "2MB" {
		t.Errorf("GetAssetnoteWordlist() size = %s; want 2MB", size)
	}
}

func TestRemoteGetOpenRedirectPayload(t *testing.T) {
	// This function doesn't exist in remote.go, but was in the original test file.
	// If it's added to remote.go, this test can be used.
	// For now, we'll assume it's a placeholder or for a different version.
	// If GetOpenRedirectPayload is defined and uses getAssetHahwul:
	/*
		assetJSON := `{"line":"3","size":"30b"}`
		payloadData := "open_redir1\nopen_redir2\nopen_redir3"
		mockServer := startMockAssetServer(t, assetJSON, payloadData)
		defer mockServer.Close()
		originalHTTPGet := httpGet
		httpGet = mockServer.Client().Get
		defer func() { httpGet = originalHTTPGet }()

		payloads := GetOpenRedirectPayload() // Assuming it's defined
		if len(payloads) != 3 {
			t.Errorf("Expected 3 open redirect payloads, got %d", len(payloads))
		}
	*/
	t.Skip("GetOpenRedirectPayload is not defined in the provided remote.go. Skipping test.")
}

func TestRemoteGetCRLFPayload(t *testing.T) {
	t.Skip("GetCRLFPayload is not defined in the provided remote.go. Skipping test.")
}

func TestRemoteGetESIIPayload(t *testing.T) {
	t.Skip("GetESIIPayload is not defined in the provided remote.go. Skipping test.")
}

func TestRemoteGetSQLIPayload(t *testing.T) {
	t.Skip("GetSQLIPayload is not defined in the provided remote.go. Skipping test.")
}

func TestRemoteGetSSTIPayload(t *testing.T) {
	t.Skip("GetSSTIPayload is not defined in the provided remote.go. Skipping test.")
}

// Helper function to compare string slices
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Test for splitLines (used internally by getAssetHahwul if not directly, it's a common pattern)
// Assuming splitLines is defined as in xss.go, or a similar local version is used.
// If it's directly from xss.go, this test is redundant here but good for understanding behavior.
func TestSplitLines_remote(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		want  []string
		isNil bool // if want is nil
	}{
		{"empty string", "", []string{}, false}, // bufio.Scanner on "" yields no lines
		{"single line", "hello", []string{"hello"}, false},
		{"multiple lines", "hello\nworld", []string{"hello", "world"}, false},
		{"trailing newline", "hello\n", []string{"hello"}, false},
		{"leading newline", "\nhello", []string{"", "hello"}, false}, // Scanner sees an empty line first
		{"multiple blank lines", "\n\n\n", []string{"", "", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Assuming splitLines is available (e.g. copied from xss.go or similar)
			// If splitLines is not in this package, this test would need to be adapted or removed.
			// For the purpose of this exercise, let's assume splitLines is defined as in xss.go.
			var lines []string
			if tt.s == "" && tt.isNil { // Special case for truly nil vs empty slice
				lines = splitLines(tt.s) // if splitLines can return nil
				if lines != nil {
					// t.Errorf("splitLines(%q) = %v, want nil", tt.s, lines)
				}
			} else if tt.s == "" && len(tt.want) == 0 {
				lines = splitLines(tt.s)
				if len(lines) != 0 {
					t.Errorf("splitLines(%q) = %v, want empty slice []", tt.s, lines)
				}

			} else {
				lines = splitLines(tt.s)
				if !equalSlices(lines, tt.want) {
					t.Errorf("splitLines(%q) = %v, want %v", tt.s, lines, tt.want)
				}
			}
		})
	}
}

/*
// Example of how to test the actual functions like GetPortswiggerPayload if they directly use the global http.Get
// This requires the httpGet variable to be correctly patched.
func TestGetPortswiggerPayload_WithProperMocking(t *testing.T) {
	mockAPIContent := `{"line":"123","size":"1.2MB"}`
	mockDataContent := "payload_one\npayload_two"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check r.URL.Path to serve different content for different endpoints if needed
		// e.g. if r.URL.Path == "/xss-portswigger.json"
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockAPIContent)
		} else if strings.HasSuffix(r.URL.Path, ".txt") {
			fmt.Fprintln(w, mockDataContent)
		}
	}))
	defer server.Close()

	// Patch the httpGet variable that getAssetHahwul uses
	originalHTTPGet := httpGet
	httpGet = func(url string) (*http.Response, error) {
		// Rewrite the URL to use the mock server
		// This is tricky because getAssetHahwul constructs the full URL internally.
		// A more robust way is to modify getAssetHahwul to accept a base URL or an http.Client.
		// For now, we assume the global httpGet is patched.
		// The key is that the patched httpGet needs to know WHICH original URL was intended.
		// Example: if url == "https://assets.hahwul.com/xss-portswigger.json"
		if strings.HasSuffix(url, "xss-portswigger.json") {
			return server.Client().Get(server.URL + "/xss-portswigger.json")
		}
		if strings.HasSuffix(url, "xss-portswigger.txt") {
			return server.Client().Get(server.URL + "/xss-portswigger.txt")
		}
		// Add other endpoints if GetPortswiggerPayload calls different ones or if other tests need it
		return nil, fmt.Errorf("unmocked URL: %s", url)
	}
	defer func() { httpGet = originalHTTPGet }()


	payloads, line, size := GetPortswiggerPayload()

	expectedPayloads := []string{"payload_one", "payload_two"}
	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("GetPortswiggerPayload() payloads = %v, want %v", payloads, expectedPayloads)
	}
	if line != "123" {
		t.Errorf("GetPortswiggerPayload() line = %q, want %q", line, "123")
	}
	if size != "1.2MB" {
		t.Errorf("GetPortswiggerPayload() size = %q, want %q", size, "1.2MB")
	}
}
*/

// Dummy Asset struct for testing JSON unmarshalling logic within getAssetHahwul if needed
type testAsset struct {
	Line string `json:"line"`
	Size string `json:"size"`
}

func TestGetAssetHahwul_JsonUnmarshalError(t *testing.T) {
	// Simulate a scenario where JSON unmarshalling fails
	mockAPIContent := `{"line": 123, "size": "not a string field for Line"}` // Invalid: line is number
	mockDataContent := "payload1\npayload2"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") { // Simplified to any .json for this test's purpose
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockAPIContent)
		} else {
			fmt.Fprintln(w, mockDataContent)
		}
	}))
	originalBaseURL := assetHahwulBaseURL
	assetHahwulBaseURL = server.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		server.Close()
	}()

	// The actual Asset struct in remote.go is { Line string, Size string }
	// If json.Unmarshal receives a number for 'Line', it will error out.
	// The function getAssetHahwul will then proceed with default/empty Asset values.
	payloads, line, size := getAssetHahwul("api.json", "data.txt") // Endpoints are relative to assets.hahwul.com

	// Payloads should still be fetched
	expectedPayloads := []string{"payload1", "payload2"}
	if !equalSlices(payloads, expectedPayloads) {
		t.Errorf("getAssetHahwul with JSON unmarshal error, payloads = %v, want %v", payloads, expectedPayloads)
	}
	// Line should be empty due to unmarshal error for the 'Line' field (type mismatch)
	if line != "" {
		t.Errorf("getAssetHahwul with JSON unmarshal error, line = %q, want \"\"", line)
	}
	// Size should be "not a string field for Line" as it's a valid string in JSON and struct
	if size != "not a string field for Line" {
		t.Errorf("getAssetHahwul with JSON unmarshal error, size = %q, want %q", size, "not a string field for Line")
	}
}

func TestGetAssetHahwul_HttpErrorOnApi(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "someapi.json") { // Target specific API endpoint for error
			http.Error(w, "API down", http.StatusServiceUnavailable)
		} else {
			fmt.Fprintln(w, "somedata") // Or handle other requests if necessary
		}
	}))
	originalBaseURL := assetHahwulBaseURL
	assetHahwulBaseURL = server.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		server.Close()
	}()

	payloads, line, size := getAssetHahwul("someapi.json", "somedata.txt")

	if len(payloads) != 0 {
		t.Errorf("Expected empty payloads on API HTTP error, got %v", payloads)
	}
	if line != "" {
		t.Errorf("Expected empty line on API HTTP error, got %s", line)
	}
	if size != "" {
		t.Errorf("Expected empty size on API HTTP error, got %s", size)
	}
}

func TestGetAssetHahwul_HttpErrorOnData(t *testing.T) {
	mockAPIContent := `{"line":"1","size":"1B"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "somedata.txt") { // Target specific data endpoint for error
			http.Error(w, "Data down", http.StatusServiceUnavailable)
		} else if strings.HasSuffix(r.URL.Path, "someapi.json") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, mockAPIContent)
		} else {
			http.NotFound(w, r)
		}
	}))
	originalBaseURL := assetHahwulBaseURL
	assetHahwulBaseURL = server.URL
	defer func() {
		assetHahwulBaseURL = originalBaseURL
		server.Close()
	}()

	payloads, line, size := getAssetHahwul("someapi.json", "somedata.txt")

	if len(payloads) != 0 {
		t.Errorf("Expected empty payloads on Data HTTP error, got %v", payloads)
	}
	// Line and Size might be populated from the API call if it succeeded before data call failed.
	// The current implementation of getAssetHahwul returns empty for all if dataResp fails.
	if line != "" {
		t.Errorf("Expected empty line on Data HTTP error, got %s", line)
	}
	if size != "" {
		t.Errorf("Expected empty size on Data HTTP error, got %s", size)
	}
}
