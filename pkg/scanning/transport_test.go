package scanning

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

func Test_getTransport(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
		want func() http.RoundTripper
	}{
		{
			name: "Default transport",
			args: args{
				options: model.Options{
					Timeout: 10,
				},
			},
			want: func() http.RoundTripper {
				return &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						Renegotiation:      tls.RenegotiateOnceAsClient,
					},
					DisableKeepAlives: true,
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						DualStack: true,
					}).DialContext,
				}
			},
		},
		{
			name: "Transport with proxy",
			args: args{
				options: model.Options{
					Timeout:      10,
					ProxyAddress: "http://localhost:8080",
				},
			},
			want: func() http.RoundTripper {
				return &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						Renegotiation:      tls.RenegotiateOnceAsClient,
					},
					DisableKeepAlives: true,
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						DualStack: true,
					}).DialContext,
					Proxy: http.ProxyURL(&url.URL{
						Scheme: "http",
						Host:   "localhost:8080",
					}),
				}
			},
		},
		{
			name: "Transport with HAR writer",
			args: args{
				options: model.Options{
					Timeout: 10,
				},
			},
			want: func() http.RoundTripper {
				transport := &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						Renegotiation:      tls.RenegotiateOnceAsClient,
					},
					DisableKeepAlives: true,
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						DualStack: true,
					}).DialContext,
				}
				file, err := os.CreateTemp("", "har_writer_test")
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(file.Name())
				harWriter, err := har.NewWriter(file, &har.Creator{Name: "dalfox", Version: "v2.0.0"})
				if err != nil {
					t.Fatalf("Failed to create HAR writer: %v", err)
				}
				return har.NewRoundTripper(transport, harWriter, rewrite)
			},
		},
		{
			name: "Custom transport",
			args: args{
				options: model.Options{
					Timeout: 10,
					CustomTransport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
							MinVersion:         tls.VersionTLS12,
						},
						DisableKeepAlives: false,
					},
				},
			},
			want: func() http.RoundTripper {
				return &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS12,
					},
					DisableKeepAlives: false,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getTransport(tt.args.options)
			want := tt.want()
			if _, ok := got.(http.RoundTripper); !ok {
				t.Errorf("getTransport() = %v, want %v", got, want)
			}
		})
	}
}

// RandomHeaderTransport is a custom transport that adds a random header value
type RandomHeaderTransport struct {
	Transport     http.RoundTripper
	HeaderName    string
	ValuePrefix   string
	randGenerator *rand.Rand
}

// RoundTrip implements the http.RoundTripper interface
func (t *RandomHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Generate a random value using the local generator if available, otherwise use global
	var randomValue string
	if t.randGenerator != nil {
		randomValue = fmt.Sprintf("%s%d", t.ValuePrefix, t.randGenerator.Intn(1000))
	} else {
		randomValue = fmt.Sprintf("%s%d", t.ValuePrefix, rand.Intn(1000))
	}

	// Add the header
	reqClone.Header.Set(t.HeaderName, randomValue)

	// Use the underlying transport
	return t.Transport.RoundTrip(reqClone)
}

func TestRandomHeaderTransport(t *testing.T) {
	// Create a local random source instead of using the deprecated rand.Seed
	randomSource := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(randomSource)

	// Create a test server that returns the headers it received
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerValue := r.Header.Get("X-Random-Value")
		w.Write([]byte(headerValue))
	}))
	defer server.Close()

	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create a random header transport
	randomHeaderTransport := &RandomHeaderTransport{
		Transport:     baseTransport,
		HeaderName:    "X-Random-Value",
		ValuePrefix:   "random-",
		randGenerator: randomGenerator,
	}

	// Create a client with the random header transport
	client := &http.Client{
		Transport: randomHeaderTransport,
	}

	// Make multiple requests to verify random values
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Read the response body
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		// Verify that the response contains the random header value
		if !strings.HasPrefix(body, "random-") {
			t.Errorf("Expected response to contain random header value with prefix 'random-', got %s", body)
		}

		// Print the random value for debugging
		t.Logf("Random header value: %s", body)
	}
}

func TestCustomTransportWithDalfox(t *testing.T) {
	// Create a test server that returns the headers it received
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerValue := r.Header.Get("X-Custom-Value")
		w.Write([]byte(headerValue))
	}))
	defer server.Close()

	// Create a random header transport
	customTransport := &RandomHeaderTransport{
		Transport:   CreateDefaultTransport(10),
		HeaderName:  "X-Custom-Value",
		ValuePrefix: "custom-",
	}

	// Create Dalfox options with the custom transport
	options := model.Options{
		CustomTransport: customTransport,
		Timeout:         10,
	}

	// Get the transport from Dalfox
	transport := getTransport(options)

	// Create a client with the transport
	client := &http.Client{
		Transport: transport,
	}

	// Make a request
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Verify that the response contains the custom header value
	if !strings.HasPrefix(body, "custom-") {
		t.Errorf("Expected response to contain custom header value with prefix 'custom-', got %s", body)
	}

	// Print the custom value for debugging
	t.Logf("Custom header value: %s", body)
}

func TestTransportChain(t *testing.T) {
	// Create a test server that returns the headers it received
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header1 := r.Header.Get("X-Header1")
		header2 := r.Header.Get("X-Header2")
		w.Write([]byte(header1 + ":" + header2))
	}))
	defer server.Close()

	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create two header transports
	headerTransport1 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Header1": "Value1",
		},
	}

	headerTransport2 := &HeaderTransport{
		Transport: headerTransport1, // Chain to the first transport
		Headers: map[string]string{
			"X-Header2": "Value2",
		},
	}

	// Create a client with the chained transport
	client := &http.Client{
		Transport: headerTransport2,
	}

	// Make a request
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Verify that the response contains both header values
	expected := "Value1:Value2"
	if body != expected {
		t.Errorf("Expected response to be '%s', got '%s'", expected, body)
	}
}

func TestCreateTransportChain(t *testing.T) {
	// Create a test server that returns the headers it received
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header1 := r.Header.Get("X-Header1")
		header2 := r.Header.Get("X-Header2")
		header3 := r.Header.Get("X-Header3")
		w.Write([]byte(header1 + ":" + header2 + ":" + header3))
	}))
	defer server.Close()

	// Create a base transport
	baseTransport := CreateDefaultTransport(10)

	// Create three header transports
	headerTransport1 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Header1": "Value1",
		},
	}

	headerTransport2 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Header2": "Value2",
		},
	}

	headerTransport3 := &HeaderTransport{
		Transport: baseTransport,
		Headers: map[string]string{
			"X-Header3": "Value3",
		},
	}

	// Create a transport chain
	transportChain := CreateTransportChain(headerTransport1, headerTransport2, headerTransport3)

	// Create a client with the transport chain
	client := &http.Client{
		Transport: transportChain,
	}

	// Make a request
	req, _ := http.NewRequest("GET", server.URL, nil)

	// Print the request headers before sending
	t.Logf("Request headers before sending: %v", req.Header)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Print the actual headers that were sent
	t.Logf("Response body (headers received by server): %s", body)

	// Verify that the response contains all header values
	expected := "Value1:Value2:Value3"
	if body != expected {
		t.Errorf("Expected response to be '%s', got '%s'", expected, body)
	}
}
