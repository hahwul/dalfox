package scanning

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func Test_performScanning(t *testing.T) {
	// Create a basic test server to handle requests
	server := mockServer()
	defer server.Close()

	type args struct {
		target  string
		options model.Options
		query   map[*http.Request]map[string]string
		durls   []string
		rl      *rateLimiter
		vStatus map[string]bool
	}

	// Create a simple test case
	simpleReq, _ := http.NewRequest("GET", server.URL+"/?param=test", nil)
	simpleQuery := map[*http.Request]map[string]string{
		simpleReq: {
			"type":    "inHTML",
			"param":   "param",
			"payload": "<script>alert(1)</script>",
		},
	}

	tests := []struct {
		name     string
		args     args
		wantPocs int
	}{
		{
			name: "Basic test case",
			args: args{
				target:  server.URL,
				options: model.Options{Concurrence: 1, Format: "plain", Silence: true, NoSpinner: true},
				query:   simpleQuery,
				durls:   []string{},
				rl:      createTestRateLimiter(0), // No rate limiting for tests
				vStatus: map[string]bool{"param": false},
			},
			wantPocs: 0, // Expecting no POCs from a mock server that doesn't reflect input
		},
		{
			name: "Empty query test case",
			args: args{
				target:  server.URL,
				options: model.Options{Concurrence: 1, Format: "plain", Silence: true, NoSpinner: true},
				query:   map[*http.Request]map[string]string{},
				durls:   []string{},
				rl:      createTestRateLimiter(0),
				vStatus: map[string]bool{},
			},
			wantPocs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := performScanning(tt.args.target, tt.args.options, tt.args.query, tt.args.durls, tt.args.rl, tt.args.vStatus)
			if len(got) != tt.wantPocs {
				t.Errorf("performScanning() returned %v PoCs, want %v", len(got), tt.wantPocs)
			}
		})
	}
}

// mockServer creates a test HTTP server that returns simple responses
func mockServer() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Mock response</body></html>"))
	})

	return httptest.NewServer(handler)
}

// createTestRateLimiter creates a simple rate limiter for testing
func createTestRateLimiter(rps int) *rateLimiter {
	// Create a new rate limiter using the package function but customize for testing
	rl := newRateLimiter(time.Duration(0))
	return rl
}
