package scanning

import (
	"crypto/tls"
	"fmt"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"net"
	"net/http"
	"net/url"
	"time"
)

// getTransport is setting timetout and proxy on tranport
func getTransport(options model.Options) *http.Transport {
	// set timeout
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			DualStack: true,
		}).DialContext,
	}
	// if use proxy mode , set proxy
	if options.ProxyAddress != "" {
		proxyAddress, err := url.Parse(options.ProxyAddress)
		_ = proxyAddress
		if err != nil {
			msg := fmt.Sprintf("not running %v from proxy option", err)
			printing.DalLog("ERROR", msg, options)
		}
		transport.Proxy = http.ProxyURL(proxyAddress)
	}
	return transport
}
