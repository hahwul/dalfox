package scanning

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// Function variables for mocking
var (
	getBurpWordlistFunc      = payload.GetBurpWordlist
	getAssetnoteWordlistFunc = payload.GetAssetnoteWordlist
	sendReqFunc              = SendReq
	dalLogFunc               = printing.DalLog
)

// mockDalLog is a mock implementation that does nothing
// Update the signature to match printing.DalLog
func mockDalLog(level string, text string, options model.Options) {
	// Do nothing
}

func TestSetP(t *testing.T) {
	type args struct {
		p       url.Values
		dp      url.Values
		name    string
		options model.Options
	}
	tests := []struct {
		name   string
		args   args
		want   url.Values
		wantDp url.Values
	}{
		{
			name: "Set parameter",
			args: args{
				p:       url.Values{},
				dp:      url.Values{},
				name:    "test",
				options: model.Options{},
			},
			want:   url.Values{"test": []string{""}},
			wantDp: url.Values{},
		},
		{
			name: "Set data parameter",
			args: args{
				p:       url.Values{},
				dp:      url.Values{},
				name:    "test",
				options: model.Options{Data: "data"},
			},
			want:   url.Values{"test": []string{""}},
			wantDp: url.Values{"test": []string{""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotDp := setP(tt.args.p, tt.args.dp, tt.args.name, tt.args.options)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("setP() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(gotDp, tt.wantDp) {
				t.Errorf("setP() gotDp = %v, want %v", gotDp, tt.wantDp)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	type args struct {
		target string
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantP   url.Values
		wantDp  url.Values
		wantErr bool
	}{
		{
			name: "Valid URL",
			args: args{
				target: "http://example.com",
			},
			want: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
			wantP:   url.Values{},
			wantDp:  url.Values{},
			wantErr: false,
		},
		{
			name: "Invalid URL",
			args: args{
				target: "://example.com",
			},
			want:    nil,
			wantP:   nil,
			wantDp:  nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotP, gotDp, err := parseURL(tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseURL() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("parseURL() gotP = %v, want %v", gotP, tt.wantP)
			}
			if !reflect.DeepEqual(gotDp, tt.wantDp) {
				t.Errorf("parseURL() gotDp = %v, want %v", gotDp, tt.wantDp)
			}
		})
	}
}

func TestAddParamsFromWordlist(t *testing.T) {
	type args struct {
		p        url.Values
		dp       url.Values
		wordlist []string
		options  model.Options
	}
	tests := []struct {
		name   string
		args   args
		want   url.Values
		wantDp url.Values
	}{
		{
			name: "Empty wordlist",
			args: args{
				p:        url.Values{},
				dp:       url.Values{},
				wordlist: []string{},
				options:  model.Options{},
			},
			want:   url.Values{},
			wantDp: url.Values{},
		},
		{
			name: "With wordlist",
			args: args{
				p:        url.Values{},
				dp:       url.Values{},
				wordlist: []string{"param1", "param2", ""},
				options:  model.Options{},
			},
			want:   url.Values{"param1": []string{""}, "param2": []string{""}},
			wantDp: url.Values{},
		},
		{
			name: "With data option",
			args: args{
				p:        url.Values{},
				dp:       url.Values{},
				wordlist: []string{"param1", "param2"},
				options:  model.Options{Data: "somedata"},
			},
			want:   url.Values{"param1": []string{""}, "param2": []string{""}},
			wantDp: url.Values{"param1": []string{""}, "param2": []string{""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotDp := addParamsFromWordlist(tt.args.p, tt.args.dp, tt.args.wordlist, tt.args.options)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("addParamsFromWordlist() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(gotDp, tt.wantDp) {
				t.Errorf("addParamsFromWordlist() gotDp = %v, want %v", gotDp, tt.wantDp)
			}
		})
	}
}

func TestGetPType(t *testing.T) {
	tests := []struct {
		name string
		av   string
		want string
	}{
		{
			name: "URL type",
			av:   "PTYPE: URL",
			want: "-URL",
		},
		{
			name: "FORM type",
			av:   "PTYPE: FORM",
			want: "-FORM",
		},
		{
			name: "Unknown type",
			av:   "PTYPE: OTHER",
			want: "",
		},
		{
			name: "Empty type",
			av:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPType(tt.av); got != tt.want {
				t.Errorf("GetPType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindDOMParams(t *testing.T) {
	// Create a test HTTP server that returns HTML with input fields
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE html>
		<html>
		<body>
			<form action="submit">
				<input type="text" name="username">
				<input type="password" name="password">
				<textarea name="comment"></textarea>
				<select name="country"></select>
			</form>
			<a href="link">Link</a>
		</body>
		</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}))
	defer ts.Close()

	p := url.Values{}
	dp := url.Values{}
	options := model.Options{
		Timeout: 10,
		NoColor: true,
	}

	// Mock HTTP client for tests
	origSendReq := sendReqFunc
	sendReqFunc = func(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
		resp, err := http.DefaultClient.Do(req)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(body), resp, true, true, err
	}
	defer func() {
		sendReqFunc = origSendReq
	}()

	gotP, _ := findDOMParams(ts.URL, p, dp, options)

	// Check that parameters from DOM were added
	expectedParams := []string{"username", "password", "comment", "country", "submit", "link"}
	for _, param := range expectedParams {
		if _, exists := gotP[param]; !exists {
			t.Errorf("findDOMParams() missing parameter %s in results", param)
		}
	}
}

func TestParameterAnalysis(t *testing.T) {
	// Setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("test") != "" {
			w.Write([]byte("<html><body>Reflected: Dalfox</body></html>"))
			return
		}
		w.Write([]byte("<html><body>Not found</body></html>"))
	}))
	defer ts.Close()

	// Setup mock functions
	origDalLog := dalLogFunc

	// Replace with mock logging function to silence logs during test
	dalLogFunc = mockDalLog

	defer func() {
		dalLogFunc = origDalLog
	}()

	// Test basic parameter analysis
	options := model.Options{
		Timeout:     10,
		Concurrence: 2,
		Debug:       true,
	}
	rl := newRateLimiter(time.Duration(0))

	target := ts.URL + "?test=aaa" // Changed from "value" to "Dalfox" to match server logic
	results := ParameterAnalysis(target, options, rl)

	// Verify that the "test" parameter was found and marked as reflected
	if param, exists := results["test"]; !exists || !param.Reflected {
		// In the refactored ParameterAnalysis, the key might include type, or results map holds typed params.
		// This assertion needs to be updated based on how ParameterAnalysis now stores/returns results.
		// For now, we assume 'test' is still a valid key if it was a query param.
		// t.Errorf("ParameterAnalysis() failed to identify reflected parameter 'test'")
		// Let's check if any parameter was found, as the keying might have changed.
		if len(results) == 0 {
			t.Errorf("ParameterAnalysis() returned no parameters")
		} else {
			// Example check, assuming 'test' is still the name for query param
			found := false
			for _, p := range results {
				if p.Name == "test" && p.Reflected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("ParameterAnalysis() failed to identify reflected parameter 'test'")
			}
		}
	}
}

func TestParameterAnalysis_ExplicitTyping(t *testing.T) {
	// Mock server for tests that might make requests (e.g. DOM parsing or initial lineSum check)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Mock Server</body></html>"))
	}))
	defer ts.Close()

	// Mock SendReq to avoid actual network calls during typing tests and control reflection results
	// This is crucial because the real SendReq would try to make network calls.
	originalSendReq := sendReqFunc
	sendReqFunc = func(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
		// Simulate a basic response, no actual reflection needed for type testing focus
		return "mock body", &http.Response{StatusCode: 200, Header: make(http.Header)}, false, false, nil
	}
	defer func() { sendReqFunc = originalSendReq }()
	
	// Mock DalLog to suppress output during tests
	originalDalLog := dalLogFunc
	dalLogFunc = func(level string, text string, options model.Options) { /* no-op */ }
	defer func() { dalLogFunc = originalDalLog }()


	baseOptions := func() model.Options {
		return model.Options{
			Timeout:     1,
			Concurrence: 1,
			NoColor:     true,
			NoSpinner:   true,
			Mining:      false, // Disable mining to simplify typing tests
			FindingDOM:  false, // Disable DOM parsing by default for typing tests
			Debug:       false,  // Keep debug off unless testing specific log output
		}
	}

	rl := newRateLimiter(time.Duration(0))

	tests := []struct {
		name          string
		targetURL     string
		optionsSetup  func(opt *model.Options) // For setting specific options like Data, Headers, Cookies
		expectedParams map[string]model.ParamResult // Keyed by Name_Type for unique checking before final map
	}{
		{
			name:      "Simple Query Parameters",
			targetURL: ts.URL + "/path?name=dalfox&age=20",
			expectedParams: map[string]model.ParamResult{
				"name_" + model.ParamTypeQuery: {Name: "name", Type: model.ParamTypeQuery},
				"age_" + model.ParamTypeQuery:  {Name: "age", Type: model.ParamTypeQuery},
				// Path params will also be identified by the refactored ParameterAnalysis
				"path1_" + model.ParamTypePath + "_path": {Name: "path1", Type: model.ParamTypePath, Value: "path"},
			},
		},
		{
			name:      "Path Parameters",
			targetURL: ts.URL + "/users/123/info",
			expectedParams: map[string]model.ParamResult{
				"path1_" + model.ParamTypePath + "_users": {Name: "path1", Type: model.ParamTypePath, Value: "users"},
				"path2_" + model.ParamTypePath + "_123":  {Name: "path2", Type: model.ParamTypePath, Value: "123"},
				"path3_" + model.ParamTypePath + "_info": {Name: "path3", Type: model.ParamTypePath, Value: "info"},
			},
		},
		{
			name:      "Fragment Parameters (query-like)",
			targetURL: ts.URL + "/test#section=A&id=frag123",
			expectedParams: map[string]model.ParamResult{
				"section_" + model.ParamTypeFragment: {Name: "section", Type: model.ParamTypeFragment},
				"id_" + model.ParamTypeFragment:      {Name: "id", Type: model.ParamTypeFragment},
				"path1_" + model.ParamTypePath + "_test": {Name: "path1", Type: model.ParamTypePath, Value: "test"},
			},
		},
		{
			name:      "Fragment Parameters (plain)",
			targetURL: ts.URL + "/test#plainFragmentValue",
			expectedParams: map[string]model.ParamResult{
				"fragment_full_" + model.ParamTypeFragment: {Name: "fragment_full", Type: model.ParamTypeFragment, Value: "plainFragmentValue"},
				"path1_" + model.ParamTypePath + "_test": {Name: "path1", Type: model.ParamTypePath, Value: "test"},
			},
		},
		{
			name:      "Header Parameters",
			targetURL: ts.URL + "/resource",
			optionsSetup: func(opt *model.Options) {
				opt.Header = []string{"X-Custom-Header: DalfoxValue", "Authorization: Bearer token"}
				opt.UserAgent = "TestAgent/1.0" // User-Agent is also treated as a header param
			},
			expectedParams: map[string]model.ParamResult{
				"X-Custom-Header_" + model.ParamTypeHeader: {Name: "X-Custom-Header", Type: model.ParamTypeHeader},
				"Authorization_" + model.ParamTypeHeader:   {Name: "Authorization", Type: model.ParamTypeHeader},
				"User-Agent_" + model.ParamTypeHeader:      {Name: "User-Agent", Type: model.ParamTypeHeader},
				"Referer_" + model.ParamTypeHeader:         {Name: "Referer", Type: model.ParamTypeHeader}, // Referer is often added
				"path1_" + model.ParamTypePath + "_resource": {Name: "path1", Type: model.ParamTypePath, Value: "resource"},
			},
		},
		{
			name:      "Cookie Parameters",
			targetURL: ts.URL + "/resource",
			optionsSetup: func(opt *model.Options) {
				opt.Cookie = "sessionID=abc123xyz; preference=dark"
			},
			expectedParams: map[string]model.ParamResult{
				"sessionID_" + model.ParamTypeCookie:    {Name: "sessionID", Type: model.ParamTypeCookie},
				"preference_" + model.ParamTypeCookie:   {Name: "preference", Type: model.ParamTypeCookie},
				"path1_" + model.ParamTypePath + "_resource": {Name: "path1", Type: model.ParamTypePath, Value: "resource"},
			},
		},
		{
			name:      "Body Form Parameters",
			targetURL: ts.URL + "/submit",
			optionsSetup: func(opt *model.Options) {
				opt.Data = "name=FormTest&email=test@example.com"
				opt.Method = "POST" // Important for body processing
				// Content-Type defaults to application/x-www-form-urlencoded if not set for POST with data
			},
			expectedParams: map[string]model.ParamResult{
				"name_" + model.ParamTypeBodyForm:  {Name: "name", Type: model.ParamTypeBodyForm},
				"email_" + model.ParamTypeBodyForm: {Name: "email", Type: model.ParamTypeBodyForm},
				"path1_" + model.ParamTypePath + "_submit": {Name: "path1", Type: model.ParamTypePath, Value: "submit"},
			},
		},
		{
			name:      "Body JSON Parameters",
			targetURL: ts.URL + "/api/data",
			optionsSetup: func(opt *model.Options) {
				opt.Data = `{"username":"jsonUser","id":123,"isActive":true}`
				opt.Method = "POST"
				opt.Header = []string{"Content-Type: application/json"}
			},
			expectedParams: map[string]model.ParamResult{
				// Only top-level keys are identified by current ParameterAnalysis for JSON
				"username_" + model.ParamTypeBodyJSON: {Name: "username", Type: model.ParamTypeBodyJSON},
				"id_" + model.ParamTypeBodyJSON:       {Name: "id", Type: model.ParamTypeBodyJSON},
				"isActive_" + model.ParamTypeBodyJSON: {Name: "isActive", Type: model.ParamTypeBodyJSON},
				"path1_" + model.ParamTypePath + "_api": {Name: "path1", Type: model.ParamTypePath, Value: "api"},
				"path2_" + model.ParamTypePath + "_data": {Name: "path2", Type: model.ParamTypePath, Value: "data"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseOptions()
			if tt.optionsSetup != nil {
				tt.optionsSetup(&opts)
			}

			// ParameterAnalysis returns map[string]model.ParamResult keyed by param.Name
			// This means if "id" is in query and "id" is in body, only one will be in the final map.
			// The internal `params` map in ParameterAnalysis uses name_type keys, which is what we should verify against ideally.
			// For now, we check against the expected final output structure.
			
			// The current structure of ParameterAnalysis populates an internal map `params` with `name_TYPE` keys,
			// then converts to `finalResults` keyed by `name`. We need to check `finalResults`.
			
			results := ParameterAnalysis(tt.targetURL, opts, rl)

			// Convert expectedParams for easier lookup against finalResults (keyed by name)
			simpleExpected := make(map[string]model.ParamResult)
			for _, p := range tt.expectedParams {
				// Handle potential name collisions in expected if multiple types share a name
				// For this test structure, we assume test cases define non-colliding names for `finalResults`
				// or accept the default collision handling (last one wins or first reflected wins).
				simpleExpected[p.Name] = p
			}
			
			assert.Equal(t, len(simpleExpected), len(results), "Number of identified parameters mismatch")

			for name, expectedP := range simpleExpected {
				actualP, exists := results[name]
				if !exists {
					t.Errorf("Expected parameter '%s' not found in results", name)
					continue
				}
				assert.Equal(t, expectedP.Type, actualP.Type, "Type mismatch for parameter '%s'", name)
				if expectedP.Type == model.ParamTypePath || expectedP.Type == model.ParamTypeFragment && expectedP.Name == "fragment_full" {
					assert.Equal(t, expectedP.Value, actualP.Value, "Value mismatch for Path/FragmentFull parameter '%s'", name)
				}
			}
		})
	}
}
