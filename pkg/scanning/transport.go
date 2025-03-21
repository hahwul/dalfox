package scanning

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/tidwall/sjson"
)

// CreateDefaultTransport creates a default transport with the given timeout
func CreateDefaultTransport(timeoutSeconds int) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSeconds) * time.Second,
			DualStack: true,
		}).DialContext,
	}
}

// getTransport is setting timetout and proxy on tranport
func getTransport(options model.Options) http.RoundTripper {
	var transport http.RoundTripper

	// Use custom transport if provided
	if options.CustomTransport != nil {
		transport = options.CustomTransport
	} else {
		// set timeout with default transport
		transport = CreateDefaultTransport(options.Timeout)
	}

	// Apply proxy settings if needed
	// Note: This will only work if the transport is of type *http.Transport
	if options.ProxyAddress != "" && transport != nil {
		if httpTransport, ok := transport.(*http.Transport); ok {
			proxyAddress, err := url.Parse(options.ProxyAddress)
			if err != nil {
				msg := fmt.Sprintf("not running %v from proxy option", err)
				printing.DalLog("ERROR", msg, options)
			} else {
				httpTransport.Proxy = http.ProxyURL(proxyAddress)
			}
		} else {
			// If custom transport is not *http.Transport, log a warning
			printing.DalLog("WARN", "Custom transport is not of type *http.Transport, proxy settings will not be applied", options)
		}
	}

	// Apply HAR writer if needed
	if options.HarWriter == nil {
		return transport
	}

	return har.NewRoundTripper(transport, options.HarWriter, rewrite)
}

func rewrite(request *http.Request, response *http.Response, entry json.RawMessage) json.RawMessage {
	messageID := har.MessageIDFromRequest(request)
	entry, _ = sjson.SetBytes(entry, "_messageId", messageID)
	return entry
}

// TransportChain is a chain of RoundTrippers
type TransportChain struct {
	transports    []http.RoundTripper
	baseTransport http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface
func (tc *TransportChain) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Apply all header transports first
	for _, transport := range tc.transports {
		if ht, ok := transport.(*HeaderTransport); ok {
			// Apply headers from this transport
			for key, value := range ht.Headers {
				reqClone.Header.Set(key, value)
			}
		}
	}

	// Then use the base transport for the actual request
	return tc.baseTransport.RoundTrip(reqClone)
}

// CreateTransportChain creates a chain of transports
func CreateTransportChain(transports ...http.RoundTripper) http.RoundTripper {
	if len(transports) == 0 {
		return http.DefaultTransport
	}
	if len(transports) == 1 {
		return transports[0]
	}

	// Find a base transport to use for the actual request
	baseTransport := http.DefaultTransport
	for _, t := range transports {
		if ht, ok := t.(*HeaderTransport); ok {
			if ht.Transport != nil {
				baseTransport = ht.Transport
				break
			}
		}
	}

	// Create a new chain with all transports
	return &TransportChain{
		transports:    transports,
		baseTransport: baseTransport,
	}
}
