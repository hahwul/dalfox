package scanning

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/hahwul/dalfox/v2/pkg/har"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/tidwall/sjson"
	"net"
	"net/http"
	"net/url"
	"time"
)

// getTransport is setting timetout and proxy on tranport
func getTransport(options model.Options) http.RoundTripper {
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
