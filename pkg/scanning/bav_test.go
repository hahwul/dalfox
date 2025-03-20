package scanning

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
)

func TestRunBAVAnalysis(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("BAV Test Response"))
	}))
	defer server.Close()

	// Set up test options with all required fields
	options := model.Options{
		Timeout:      10,
		Concurrence:  1,
		Delay:        0,
		AuroraObject: aurora.NewAurora(false), // No color for testing
		NoSpinner:    true,
	}

	// Create a rate limiter with no delay for testing
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	// Create a variable to store the result
	bav := ""

	// Run the BAV analysis
	RunBAVAnalysis(server.URL+"?param=test", options, rl, &bav)

	// Verify that bav was modified (exact value will depend on terminal colors)
	if bav == "" {
		t.Error("BAV analysis did not update the bav variable")
	}
}

func TestSSTIAnalysis(t *testing.T) {
	// Create a test server
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SSTI Test Response"))
	}))
	defer server.Close()

	// Set up test options with a minimal configuration
	options := model.Options{
		Timeout:     10,
		Concurrence: 1,
	}

	// Run the SSTI analysis with a rate limiter
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	SSTIAnalysis(server.URL+"?param=test", options, rl)

	// Verify requests were made (exact number depends on SSTI payload count)
	if requestCount == 0 {
		t.Error("No requests were made during SSTI analysis")
	}
}

func TestCRLFAnalysis(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CRLF Test Response"))
	}))
	defer server.Close()

	options := model.Options{
		Timeout:     10,
		Concurrence: 1,
	}

	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	CRLFAnalysis(server.URL+"?param=test", options, rl)

	if requestCount == 0 {
		t.Error("No requests were made during CRLF analysis")
	}
}

func TestESIIAnalysis(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ESII Test Response"))
	}))
	defer server.Close()

	options := model.Options{
		Timeout:     10,
		Concurrence: 1,
	}

	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	ESIIAnalysis(server.URL+"?param=test", options, rl)

	if requestCount == 0 {
		t.Error("No requests were made during ESII analysis")
	}
}

func TestSqliAnalysis(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SQLi Test Response"))
	}))
	defer server.Close()

	options := model.Options{
		Timeout:     10,
		Concurrence: 1,
	}

	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	SqliAnalysis(server.URL+"?param=test", options, rl)

	if requestCount == 0 {
		t.Error("No requests were made during SQLi analysis")
	}
}

func TestOpenRedirectorAnalysis(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		params := r.URL.Query()
		redirect := params.Get("param")

		// Test if the parameter contains an open redirect payload
		if redirect != "test" {
			w.Header().Set("Location", redirect)
			w.WriteHeader(http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	options := model.Options{
		Timeout:     10,
		Concurrence: 1,
	}

	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	OpenRedirectorAnalysis(server.URL+"?param=test", options, rl)

	if requestCount == 0 {
		t.Error("No requests were made during Open Redirector analysis")
	}
}
