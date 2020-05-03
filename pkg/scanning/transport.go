package scanning

import (
	"crypto/tls"
	"fmt"
	"github.com/hahwul/dalfox/pkg/printing"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// getTransport is setting timetout and proxy on tranport
func getTransport(optionsStr map[string]string) *http.Transport {
	// set timeout
	t, _ := strconv.Atoi(optionsStr["timeout"])
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(t) * time.Second,
			DualStack: true,
		}).DialContext,
	}
	// if use proxy mode , set proxy
	if optionsStr["proxy"] != "" {
		proxyAddress, err := url.Parse(optionsStr["proxy"])
		_ = proxyAddress
		if err != nil {
			msg := fmt.Sprintf("not running %v from proxy option", err)
			printing.DalLog("ERROR", msg, optionsStr)
		}
		transport.Proxy = http.ProxyURL(proxyAddress)
	}
	return transport
}
