package printing

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestMakePoC(t *testing.T) {
	type args struct {
		poc     string
		req     *http.Request
		options model.Options
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "HTTP RAW REQUEST",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
					return req
				}(),
				options: model.Options{
					PoCType: "http-request",
				},
			},
			want: "HTTP RAW REQUEST\nGET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
		},
		{
			name: "curl with body",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					body := ioutil.NopCloser(strings.NewReader("test body"))
					req, _ := http.NewRequest(http.MethodPost, "http://example.com", body)
					req.GetBody = func() (io.ReadCloser, error) {
						return ioutil.NopCloser(strings.NewReader("test body")), nil
					}
					return req
				}(),
				options: model.Options{
					PoCType: "curl",
				},
			},
			want: "curl -i -k -X POST http://example.com -d \"test body\"",
		},
		{
			name: "httpie with body",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					body := ioutil.NopCloser(strings.NewReader("test body"))
					req, _ := http.NewRequest(http.MethodPost, "http://example.com", body)
					req.GetBody = func() (io.ReadCloser, error) {
						return ioutil.NopCloser(strings.NewReader("test body")), nil
					}
					return req
				}(),
				options: model.Options{
					PoCType: "httpie",
				},
			},
			want: "http POST http://example.com \"test body\" --verify=false -f",
		},
		{
			name: "curl without body",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
					return req
				}(),
				options: model.Options{
					PoCType: "curl",
				},
			},
			want: "curl -i -k http://example.com",
		},
		{
			name: "httpie without body",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
					return req
				}(),
				options: model.Options{
					PoCType: "httpie",
				},
			},
			want: "http http://example.com --verify=false",
		},
		{
			name: "default without body",
			args: args{
				poc: "http://example.com",
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
					return req
				}(),
				options: model.Options{
					PoCType: "default",
				},
			},
			want: "http://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MakePoC(tt.args.poc, tt.args.req, tt.args.options); got != tt.want {
				t.Errorf("MakePoC() = %v, want %v", got, tt.want)
			}
		})
	}
}
