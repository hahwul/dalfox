package scanning

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
	"github.com/stretchr/testify/assert"
)

// mockServerForMagicTest is a simple HTTP server for magic tests.
func mockServerForMagicTest() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflect query params for basic verification if needed
		for k, v := range r.URL.Query() {
			fmt.Fprintf(w, "%s: %s\n", k, strings.Join(v, ","))
		}
		// Reflect headers for basic verification
		for k, v := range r.Header {
			// Don't reflect all headers, just a known test one if set
			if k == "X-Test-Header" {
				fmt.Fprintf(w, "%s: %s\n", k, strings.Join(v, ","))
			}
		}
		// Reflect body params for basic verification if POST
		if r.Method == "POST" {
			r.ParseForm()
			for k, v := range r.PostForm {
				fmt.Fprintf(w, "body_%s: %s\n", k, strings.Join(v, ","))
			}
		}
		fmt.Fprintln(w, "<html><body>Mock server response</body></html>")
	}))
}

// Helper to create base options for tests
func getTestOptions() model.Options {
	return model.Options{
		Concurrence:     1,
		Timeout:         10,
		Format:          "plain",
		Silence:         false, // We want to capture logs
		NoSpinner:       true,
		NoColor:         true,
		CustomAlertType: "none",
		AuroraObject:    aurora.NewAurora(true), // NoColor = true
		Scan:            make(map[string]model.Scan),
		PathReflection:  make(map[int]string),
		Mutex:           &sync.Mutex{},
		// Default to skip discovery for most magic tests unless specific test needs it
		// This helps isolate the magic param handling from discovery logic.
		// Test cases will override this if they need to check interaction.
		// SkipDiscovery: true,
	}
}

// TestMagicCharacterInQueryParameter tests detection of magic string in a query parameter.
func TestMagicCharacterInQueryParameter(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "DALFOX_MAGIC_TEST"
	options := getTestOptions()
	options.MagicString = magicStr
	options.OnlyDiscovery = true // To prevent actual scanning, focus on detection and setup

	targetURL := server.URL + "/?query1=value1&query2=prefix" + magicStr + "suffix&query3=value3"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-query")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Should identify one magic parameter") {
		assert.Equal(t, "query2", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeQuery, options.InternalFoundMagicParams[0].Type)
	}
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: query2 (QUERY)", "Log should indicate discovery bypass for query2 (QUERY)")

	// Verify params map for generatePayloads (mocked or by checking options if Scan modifies it directly)
	// For this, we need to see how `params` is populated in Scan before `generatePayloads`
	// Based on current Scan structure, `params` local to Scan is populated.
	// We can infer its state by the "Forcing XSS testing on X magic parameters" log.
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Log should indicate forcing XSS on identified param")
}

// TestMagicCharacterInHeader tests detection of magic string in a request header.
func TestMagicCharacterInHeader(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "MAGIC_IN_HEADER"
	options := getTestOptions()
	options.MagicString = magicStr
	options.Header = []string{"Normal-Header: value", "X-Magic-Header: Bearer " + magicStr, "Another-Header: test"}
	options.OnlyDiscovery = true // Focus on detection

	targetURL := server.URL + "/test"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-header")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Should identify one magic parameter") {
		assert.Equal(t, "X-Magic-Header", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeHeader, options.InternalFoundMagicParams[0].Type)
	}
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: X-Magic-Header (HEADER)", "Log should indicate discovery bypass for the header")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Log should indicate forcing XSS on identified param")
}

// TestMagicCharacterInPostBody tests detection of magic string in a POST body parameter.
func TestMagicCharacterInPostBody(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "POST_MAGIC_HERE"
	options := getTestOptions()
	options.MagicString = magicStr
	options.Method = "POST"
	options.Data = "param1=value1&magicParam=" + magicStr + "&param2=value2"
	options.OnlyDiscovery = true // Focus on detection

	targetURL := server.URL + "/submit"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-post")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Should identify one magic parameter") {
		assert.Equal(t, "magicParam", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeBodyForm, options.InternalFoundMagicParams[0].Type) // Assuming default form
	}
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: magicParam (BODY_FORM)", "Log should indicate discovery bypass for the body parameter")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Log should indicate forcing XSS on identified param")
}

// TestMagicCharacterInJsonBody tests detection of magic string in a POST JSON body .
func TestMagicCharacterInJsonBody(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "JSON_MAGIC_VAL"
	options := getTestOptions()
	options.MagicString = magicStr
	options.Method = "POST"
	options.Data = `{"key1":"value1", "magicKey":"some ` + magicStr + ` data", "key2":"value2"}`
	options.Header = []string{"Content-Type: application/json"} // Important for JSON parsing
	options.OnlyDiscovery = true 

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-json-body")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Should identify one magic JSON parameter") {
		assert.Equal(t, "magicKey", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeBodyJSON, options.InternalFoundMagicParams[0].Type)
	}
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: magicKey (BODY_JSON)", "Log should indicate discovery bypass for the JSON key")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Log should indicate forcing XSS on identified param")
}


// TestMagicCharacterNotPresent tests behavior when magic string is configured but not found.
func TestMagicCharacterNotPresent(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	options := getTestOptions()
	options.MagicString = "SUPER_SECRET_MAGIC"
	options.OnlyDiscovery = true // We expect normal discovery (or skip if SkipDiscovery is default)

	targetURL := server.URL + "/?query1=value1"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-notpresent")
	})
	capturedLogs = stdout + stderr

	assert.False(t, options.HasMagicParams, "HasMagicParams should be false")
	assert.Empty(t, options.InternalFoundMagicParams, "InternalFoundMagicParams should be empty")
	assert.Contains(t, capturedLogs, "No magic parameters identified with string: SUPER_SECRET_MAGIC", "Log should indicate no magic params found")
	// Depending on default SkipDiscovery in getTestOptions, this might change.
	// If SkipDiscovery is false (or not set) by default in getTestOptions:
	// assert.NotContains(t, capturedLogs, "Bypassing discovery", "Log should NOT indicate discovery bypass")
	// assert.Contains(t, capturedLogs, "Starting Dicovering", "Log should indicate normal discovery or parameter analysis start")
	// If SkipDiscovery is true by default in getTestOptions (as per my current plan for isolation):
	assert.NotContains(t, capturedLogs, "Bypassing discovery due to identified magic parameters", "Log should NOT indicate magic bypass")
	// And it would proceed with whatever --skip-discovery implies or if -p is used.
	// For this test, let's ensure SkipDiscovery is false to check normal flow.
	options.SkipDiscovery = false // Override default for this test
	stdout2, stderr2 := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-notpresent-normal-discovery")
	})
	capturedLogs2 := stdout2 + stderr2
	assert.False(t, optionsNoMagic.HasMagicParams, "HasMagicParams should be false (run 2)")
	assert.Empty(t, optionsNoMagic.InternalFoundMagicParams, "InternalFoundMagicParams should be empty (run 2)")
	assert.Contains(t, capturedLogs2, "No magic parameters identified with string: SUPER_SECRET_MAGIC", "Log should indicate no magic params found (run 2)")
	assert.NotContains(t, capturedLogs2, "Bypassing discovery due to identified magic parameters", "Log should NOT indicate magic bypass (run 2)")
	assert.Contains(t, capturedLogs2, "Starting Dicovering", "Log should indicate normal discovery start (run 2)")
}

// TestMultipleMagicParameters tests detection of magic string in multiple locations.
func TestMultipleMagicParameters(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "MULTI_MAGIC"
	options := getTestOptions()
	options.MagicString = magicStr
	options.Header = []string{"X-Magic-Header: " + magicStr}
	options.OnlyDiscovery = true // Focus on detection

	targetURL := server.URL + "/?queryMagic=" + magicStr + "&normalParam=val"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-multi")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 2, "Should identify two magic parameters") {
		foundQuery := false
		foundHeader := false
		for _, p := range options.InternalFoundMagicParams {
			if p.Name == "queryMagic" && p.Type == model.ParamTypeQuery {
				foundQuery = true
			}
			if p.Name == "X-Magic-Header" && p.Type == model.ParamTypeHeader {
				foundHeader = true
			}
		}
		assert.True(t, foundQuery, "queryMagic (QUERY) not found")
		assert.True(t, foundHeader, "X-Magic-Header (HEADER) not found")
	}
	// Log message might show them in different order, so check for parts
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters:")
	assert.Contains(t, capturedLogs, "queryMagic (QUERY)")
	assert.Contains(t, capturedLogs, "X-Magic-Header (HEADER)")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 2 magic parameters.", "Log should indicate forcing XSS on identified params")
}

// TestMagicWithSkipDiscovery tests interaction with --skip-discovery.
// Magic parameters should still be prioritized.
func TestMagicWithSkipDiscovery(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "MAGIC_SKIP_DISCO"
	options := getTestOptions()
	options.MagicString = magicStr
	options.SkipDiscovery = true // Explicitly set --skip-discovery
	// Provide a -p param as well, which would normally be used with --skip-discovery
	options.UniqParam = []string{"normalSkipDiscoParam"}
	options.OnlyDiscovery = true // Focus on detection and setup rather than full scan

	targetURL := server.URL + "/?magicQuery=" + magicStr

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-magic-skip")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true due to magic string")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Only the magic parameter should be in InternalFoundMagicParams") {
		assert.Equal(t, "magicQuery", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeQuery, options.InternalFoundMagicParams[0].Type)
	}
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: magicQuery (QUERY)", "Log should indicate discovery bypass for magic param")
	assert.NotContains(t, capturedLogs, "Skipping discovery phase as requested with --skip-discovery", "The specific --skip-discovery log should be superseded by magic bypass log")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Should force test on the magic parameter")

	// Further check: The `params` map used for generatePayloads should prioritize/include the magic one.
	// We are checking this via the "Forcing XSS testing on X magic parameters" log.
	// If `normalSkipDiscoParam` was also added to `params` in this scenario, the count would be different.
	// The current implementation's bypass for magic params *replaces* the params list, so `normalSkipDiscoParam` would be ignored if magic is found.
}

// TestMagicWithUniqParam tests interaction with -p (options.UniqParam).
// Magic params should be tested. Other -p params ideally too, or behavior clarified.
func TestMagicWithUniqParam(t *testing.T) {
	server := mockServerForMagicTest()
	defer server.Close()

	magicStr := "MAGIC_WITH_P"
	options := getTestOptions()
	options.MagicString = magicStr
	options.UniqParam = []string{"p_param1", "p_param2"} // User specifies these with -p
	options.OnlyDiscovery = true

	// Magic string is present, so magic logic should take precedence.
	targetURL := server.URL + "/?magicQuery=" + magicStr + "&p_param1=value"

	var capturedLogs string
	stdout, stderr := captureOutput(func() {
		Scan(targetURL, options, "test-scan-id-magic-p")
	})
	capturedLogs = stdout + stderr

	assert.True(t, options.HasMagicParams, "HasMagicParams should be true")
	if assert.Len(t, options.InternalFoundMagicParams, 1, "Only the magic parameter should be in InternalFoundMagicParams if magic logic supersedes -p for discovery bypass") {
		assert.Equal(t, "magicQuery", options.InternalFoundMagicParams[0].Name)
		assert.Equal(t, model.ParamTypeQuery, options.InternalFoundMagicParams[0].Type)
	}
	
	assert.Contains(t, capturedLogs, "Bypassing discovery due to identified magic parameters: magicQuery (QUERY)", "Log should indicate discovery bypass for magic param")
	assert.Contains(t, capturedLogs, "Forcing XSS testing on 1 magic parameters.", "Should force test only on the identified magic parameter")

	// Current behavior: If magic params are found, they *replace* what -p would have set up in combination with --skip-discovery.
	// If no magic params were found, and --skip-discovery was true, then -p params would be used.
	// If no magic params and --skip-discovery is false, normal discovery runs, and -p might influence optimization.CheckInspectionParam.

	// Test case: No magic string, but -p is present (and SkipDiscovery is false by default in getTestOptions for this test)
	optionsNoMagic := getTestOptions()
	optionsNoMagic.MagicString = "NOT_PRESENT_MAGIC"
	optionsNoMagic.UniqParam = []string{"p_param1", "p_param2"}
	optionsNoMagic.OnlyDiscovery = true
	optionsNoMagic.SkipDiscovery = false // Ensure normal discovery runs

	targetURLNoMagic := server.URL + "/?p_param1=value&other=test"
	
	stdout2, stderr2 := captureOutput(func() {
		Scan(targetURLNoMagic, optionsNoMagic, "test-scan-id-p-no-magic")
	})
	capturedLogs2 := stdout2 + stderr2

	assert.False(t, optionsNoMagic.HasMagicParams, "HasMagicParams should be false when no magic string")
	assert.Empty(t, optionsNoMagic.InternalFoundMagicParams, "InternalFoundMagicParams should be empty")
	assert.NotContains(t, capturedLogs2, "Bypassing discovery due to identified magic parameters")
	assert.Contains(t, capturedLogs2, "Starting Dicovering", "Normal discovery should run")
	// In normal discovery, options.UniqParam is used by optimization.CheckInspectionParam to focus analysis.
	// We won't see "Forcing XSS testing" log here.
	// We should see the identified -p params in the "Reflected p_param1 param" logs.
	assert.Contains(t, capturedLogs2, "Reflected p_param1 param", "p_param1 from -p should be processed in discovery")
	// p_param2 is not in URL, so it won't be "Reflected" unless found via other means (not covered by this simple mock).
}

// TestPopulateParamsForMagic correctly checks if the params map is populated for generatePayloads.
func TestPopulateParamsForMagic(t *testing.T) {
	// This test doesn't run Scan, but directly tests the logic that would populate
	// the 'params' variable if magic strings are found.
	// This is a more unit-like test for that specific part of the Scan function.

	magicStr := "TEST_POPULATE"
	options := getTestOptions() // SkipDiscovery is typically true here or not relevant
	options.MagicString = magicStr
	options.InternalFoundMagicParams = []model.ParamResult{
		{Name: "magicQuery", Type: model.ParamTypeQuery},
		{Name: "X-Magic-Header", Type: model.ParamTypeHeader},
		{Name: "magicBodyParam", Type: model.ParamTypeBodyForm}, // Example type
	}
	options.HasMagicParams = true

	// This map simulates the 'params' map that would be created inside Scan
	// and then passed to generatePayloads. It's keyed by param.Name.
	simulatedParamsMapInScan := make(map[string]model.ParamResult)
	for _, p := range options.InternalFoundMagicParams {
		simulatedParamsMapInScan[p.Name] = model.ParamResult{
			Name:      p.Name,
			Type:      p.Type,
			Reflected: true,
			Chars:     payload.GetSpecialChar(),
		}
	}

	assert.Equal(t, model.ParamTypeQuery, simulatedParamsMapInScan["magicQuery"].Type)
	assert.Equal(t, model.ParamTypeHeader, simulatedParamsMapInScan["X-Magic-Header"].Type)
	assert.Equal(t, model.ParamTypeBodyForm, simulatedParamsMapInScan["magicBodyParam"].Type)

	for _, p := range simulatedParamsMapInScan {
		assert.True(t, p.Reflected)
		assert.Equal(t, payload.GetSpecialChar(), p.Chars)
	}
	
	// This test confirms that if `options.InternalFoundMagicParams` is populated correctly by the detection phase,
	// the logic within `Scan` (that builds the 'params' map for generatePayloads) 
	// would use these types.
}
