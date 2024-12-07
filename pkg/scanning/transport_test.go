package scanning

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/har"
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
