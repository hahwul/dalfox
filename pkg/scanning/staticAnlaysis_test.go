package scanning

import (
	"net/http"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/stretchr/testify/assert"
)

type mockRequestSender struct{}

func (m *mockRequestSender) SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, string, bool, error) {
	return "response body with dalfoxpathtest", &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=UTF-8"},
		},
	}, "", true, nil
}

func Test_checkPathReflection(t *testing.T) {
	type args struct {
		tempURL        string
		id             int
		options        model.Options
		rl             *rateLimiter
		pathReflection map[int]string
	}
	tests := []struct {
		name string
		args args
		want map[int]string
	}{
		{
			name: "Path reflection found",
			args: args{
				tempURL: "http://example.com/dalfoxpathtest",
				id:      0,
				options: model.Options{},
				rl:      newRateLimiter(time.Duration(0)),
				pathReflection: map[int]string{
					0: "Injected: /dalfoxpathtest(1)",
				},
			},
			want: map[int]string{
				0: "Injected: /dalfoxpathtest(1)",
			},
		},
		{
			name: "Path reflection not found",
			args: args{
				tempURL:        "http://example.com/",
				id:             0,
				options:        model.Options{},
				rl:             newRateLimiter(time.Duration(0)),
				pathReflection: map[int]string{},
			},
			want: map[int]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkPathReflection(tt.args.tempURL, tt.args.id, tt.args.options, tt.args.rl, tt.args.pathReflection)
			assert.Equal(t, tt.want, tt.args.pathReflection)
		})
	}
}

func Test_extractPolicyHeaders(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   map[string]string
	}{
		{
			name: "All headers present",
			header: http.Header{
				"Content-Type":                []string{"text/html"},
				"Content-Security-Policy":     []string{"default-src 'self'"},
				"X-Frame-Options":             []string{"DENY"},
				"Strict-Transport-Security":   []string{"max-age=31536000; includeSubDomains"},
				"Access-Control-Allow-Origin": []string{"*"},
			},
			want: map[string]string{
				"Content-Type":                "text/html",
				"Content-Security-Policy":     "default-src 'self'",
				"X-Frame-Options":             "DENY",
				"Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			name: "Some headers missing",
			header: http.Header{
				"Content-Type":              []string{"text/html"},
				"X-Frame-Options":           []string{"DENY"},
				"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains"},
			},
			want: map[string]string{
				"Content-Type":              "text/html",
				"X-Frame-Options":           "DENY",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			},
		},
		{
			name:   "No headers present",
			header: http.Header{},
			want:   map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := make(map[string]string)
			extractPolicyHeaders(tt.header, policy)
			assert.Equal(t, tt.want, policy)
		})
	}
}

func Test_StaticAnalysis(t *testing.T) {
	tests := []struct {
		name           string
		target         string
		options        model.Options
		wantPolicy     map[string]string
		wantReflection map[int]string
	}{
		{
			name:   "Static analysis with path reflection",
			target: "http://example.com/dalfoxpathtest",
			options: model.Options{
				Timeout: 10,
				Delay:   1,
			},
			wantPolicy: map[string]string{
				"Content-Type": "text/html; charset=UTF-8",
			},
			wantReflection: map[int]string{
				0: "Injected: /dalfoxpathtest(1)",
			},
		},
		{
			name:   "Static analysis without path reflection",
			target: "http://example.com/",
			options: model.Options{
				Timeout: 10,
				Delay:   1,
			},
			wantPolicy: map[string]string{
				"Content-Type": "text/html; charset=UTF-8",
			},
			wantReflection: map[int]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := newRateLimiter(time.Duration(tt.options.Delay * 1000000))
			StaticAnalysis(tt.target, tt.options, rl)
		})
	}
}
