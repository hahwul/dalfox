package scanning

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// This file contains examples of how to use the custom transport feature.
// These examples are not meant to be run directly, but rather to serve as documentation.

// Example 1: Using a custom transport with a custom TLS configuration
func ExampleCustomTransportWithTLS() {
	// Create a custom transport with a custom TLS configuration
	customTransport := CreateDefaultTransport(10) // 10 seconds timeout
	customTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	// Create options with the custom transport
	options := model.Options{
		CustomTransport: customTransport,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options
}

// Example 2: Using a transport chain with multiple header transports
func ExampleTransportChain() {
	// Create a base transport
	baseTransport := CreateDefaultTransport(10) // 10 seconds timeout

	// Create multiple header transports
	headerTransport1 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Custom-Header1": "Value1",
		},
	}

	headerTransport2 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Custom-Header2": "Value2",
		},
	}

	// Create a transport chain with both transports
	transportChain := CreateTransportChain(headerTransport1, headerTransport2)

	// Create options with the transport chain
	options := model.Options{
		CustomTransport: transportChain,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options // Prevent unused variable warning
}

// HeaderTransport is a custom transport that adds headers to requests
type HeaderTransport struct {
	Transport http.RoundTripper
	Headers   map[string]string
}

// RoundTrip implements the http.RoundTripper interface
func (t *HeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Add headers
	for key, value := range t.Headers {
		reqClone.Header.Set(key, value)
	}

	// Use the underlying transport
	return t.Transport.RoundTrip(reqClone)
}

// Example 3: Using a retry transport for resilient scanning
func ExampleRetryTransport() {
	// Create a base transport
	baseTransport := CreateDefaultTransport(10) // 10 seconds timeout

	// Create a retry transport
	retryTransport := &RetryTransport{
		Transport:    baseTransport,
		MaxRetries:   3,
		RetryDelay:   time.Second,
		RetryBackoff: 2, // Exponential backoff
	}

	// Create options with the retry transport
	options := model.Options{
		CustomTransport: retryTransport,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options // Prevent unused variable warning
}

// RetryTransport is a custom transport that retries failed requests
type RetryTransport struct {
	Transport    http.RoundTripper
	MaxRetries   int
	RetryDelay   time.Duration
	RetryBackoff float64
}

// RoundTrip implements the http.RoundTripper interface
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Try the request
	for i := 0; i <= t.MaxRetries; i++ {
		resp, err = t.Transport.RoundTrip(reqClone)
		if err == nil && resp.StatusCode < 400 {
			return resp, nil
		}

		if i == t.MaxRetries {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		delay := t.RetryDelay
		if t.RetryBackoff > 1 {
			delay = time.Duration(float64(delay) * float64(i) * t.RetryBackoff)
		}
		time.Sleep(delay)

		reqClone = req.Clone(req.Context())
	}

	return nil, err
}

// Example 4: Using an OAuth2 transport for authenticated scanning
func ExampleOAuth2Transport() {
	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create an OAuth2 transport
	oauth2Transport := &OAuth2Transport{
		Transport:     baseTransport,
		TokenEndpoint: "https://auth.example.com/token",
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		Scope:         "read write",
	}

	// Create options with the OAuth2 transport
	options := model.Options{
		CustomTransport: oauth2Transport,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options // Prevent unused variable warning
}

// OAuth2Transport is a custom transport that adds OAuth2 authentication
type OAuth2Transport struct {
	Transport     http.RoundTripper
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Scope         string
	accessToken   string
	tokenExpiry   time.Time
	randGenerator *rand.Rand
}

// RoundTrip implements the http.RoundTripper interface
func (t *OAuth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Check if we need to refresh the token
	if t.accessToken == "" || time.Now().After(t.tokenExpiry) {
		if err := t.refreshToken(); err != nil {
			return nil, err
		}
	}

	// Add the Authorization header
	reqClone.Header.Set("Authorization", "Bearer "+t.accessToken)

	// Use the underlying transport
	return t.Transport.RoundTrip(reqClone)
}

// refreshToken refreshes the OAuth2 access token
func (t *OAuth2Transport) refreshToken() error {
	// In a real implementation, this would make a request to the token endpoint
	// For this example, we'll just simulate it

	// Initialize the random generator if not already done
	if t.randGenerator == nil {
		t.randGenerator = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	t.accessToken = fmt.Sprintf("simulated_token_%d", t.randGenerator.Intn(1000))
	t.tokenExpiry = time.Now().Add(1 * time.Hour)
	return nil
}

// Example 5: Using a rate limiting transport to avoid being blocked
func ExampleRateLimitTransport() {
	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create a rate limit transport
	rateLimitTransport := &RateLimitTransport{
		Transport:      baseTransport,
		RequestsPerSec: 5, // 5 requests per second
	}

	// Create options with the rate limit transport
	options := model.Options{
		CustomTransport: rateLimitTransport,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options // Prevent unused variable warning
}

// RateLimitTransport is a custom transport that limits the rate of requests
type RateLimitTransport struct {
	Transport      http.RoundTripper
	RequestsPerSec int
	lastRequest    time.Time
	minInterval    time.Duration
}

// RoundTrip implements the http.RoundTripper interface
func (t *RateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Calculate the minimum interval between requests
	if t.minInterval == 0 {
		t.minInterval = time.Second / time.Duration(t.RequestsPerSec)
	}

	// Wait if needed
	elapsed := time.Since(t.lastRequest)
	if elapsed < t.minInterval {
		time.Sleep(t.minInterval - elapsed)
	}

	// Update the last request time
	t.lastRequest = time.Now()

	// Use the underlying transport
	return t.Transport.RoundTrip(reqClone)
}

// Example 6: Using a logging transport for debugging
func ExampleLoggingTransport() {
	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create a logging transport
	loggingTransport := &LoggingTransport{
		Transport: baseTransport,
		LogWriter: io.Discard, // Replace with a real writer in production
	}

	// Create options with the logging transport
	options := model.Options{
		CustomTransport: loggingTransport,
		Timeout:         10,
	}

	// Use the options in a scan (not actually called in this example)
	// Scan("https://example.com", options, "1")
	_ = options // Prevent unused variable warning
}

// LoggingTransport is a custom transport that logs requests and responses
type LoggingTransport struct {
	Transport http.RoundTripper
	LogWriter io.Writer
}

// RoundTrip implements the http.RoundTripper interface
func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Log the request
	fmt.Fprintf(t.LogWriter, "[%s] %s %s\n", time.Now().Format(time.RFC3339), req.Method, req.URL)
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(t.LogWriter, "  %s: %s\n", key, value)
		}
	}

	// Use the underlying transport
	resp, err := t.Transport.RoundTrip(reqClone)
	if err != nil {
		fmt.Fprintf(t.LogWriter, "  Error: %v\n", err)
		return nil, err
	}

	// Log the response
	fmt.Fprintf(t.LogWriter, "  Response: %d %s\n", resp.StatusCode, resp.Status)
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(t.LogWriter, "    %s: %s\n", key, value)
		}
	}

	return resp, nil
}
