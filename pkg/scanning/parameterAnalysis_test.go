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
		t.Errorf("ParameterAnalysis() failed to identify reflected parameter")
	}
}
