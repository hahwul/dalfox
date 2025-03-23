package scanning

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestSendReq(t *testing.T) {
	type args struct {
		req     *http.Request
		payload string
		options model.Options
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   *http.Response
		want2   bool
		want3   bool
		wantErr bool
	}{
		{
			name: "Successful request",
			args: args{
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "https://dalfox.hahwul.com", nil)
					return req
				}(),
				payload: "test-payload",
				options: model.Options{
					Timeout: 10,
				},
			},
			want:    "dalfox",
			want1:   &http.Response{StatusCode: http.StatusOK},
			want2:   false,
			want3:   false,
			wantErr: false,
		},
		{
			name: "Request with error",
			args: args{
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "http://invalid-url", nil)
					return req
				}(),
				payload: "test-payload",
				options: model.Options{
					Timeout: 10,
				},
			},
			want:    "",
			want1:   nil,
			want2:   false,
			want3:   false,
			wantErr: true,
		},
		{
			name: "Request with trigger",
			args: args{
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "https://dalfox.hahwul.com", nil)
					return req
				}(),
				payload: "test-payload",
				options: model.Options{
					Timeout:       10,
					Trigger:       "https://dalfox.hahwul.com",
					TriggerMethod: http.MethodGet,
				},
			},
			want:    "dalfox",
			want1:   &http.Response{StatusCode: http.StatusOK},
			want2:   false,
			want3:   false,
			wantErr: false,
		},
		{
			name: "Request with ForceHeadlessVerification",
			args: args{
				req: func() *http.Request {
					req, _ := http.NewRequest(http.MethodGet, "https://dalfox.hahwul.com", nil)
					return req
				}(),
				payload: "test-payload",
				options: model.Options{
					Timeout:                   10,
					ForceHeadlessVerification: true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3, err := SendReq(tt.args.req, tt.args.payload, tt.args.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendReq() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("SendReq() got = %v, want %v", got, tt.want)
			}
			if got1 != nil && tt.want1 != nil && got1.StatusCode != tt.want1.StatusCode {
				t.Errorf("SendReq() got1 = %v, want %v", got1.StatusCode, tt.want1.StatusCode)
			}
			if got2 != tt.want2 {
				t.Errorf("SendReq() got2 = %v, want %v", got2, tt.want2)
			}
			if got3 != tt.want3 {
				t.Errorf("SendReq() got3 = %v, want %v", got3, tt.want3)
			}
		})
	}
}

func TestCreatePoC(t *testing.T) {
	// Create a request with necessary context value
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/?param=value", nil)

	// Add message ID to context with the correct type
	// Use the correct key that matches the one used in MessageIDFromRequest function
	ctx := context.WithValue(req.Context(), "message_id", int64(1))
	req = req.WithContext(ctx)

	options := model.Options{
		Method:  "GET",
		PoCType: "plain",
	}

	tests := []struct {
		name       string
		injectType string
		cwe        string
		severity   string
		req        *http.Request
		payload    string
		options    model.Options
		want       model.PoC
	}{
		{
			name:       "Basic PoC creation",
			injectType: "XSS",
			cwe:        "CWE-79",
			severity:   "High",
			req:        req,
			payload:    "<script>alert(1)</script>",
			options:    options,
			want: model.PoC{
				Type:       "G",
				InjectType: "XSS",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Param:      "",
				Payload:    "<script>alert(1)</script>",
				Evidence:   "",
				CWE:        "CWE-79",
				Severity:   "High",
				PoCType:    "plain",
			},
		},
		{
			name:       "Open Redirect PoC",
			injectType: "BAV/OR",
			cwe:        "CWE-601",
			severity:   "Medium",
			req:        req,
			payload:    "//evil.com",
			options:    options,
			want: model.PoC{
				Type:       "G",
				InjectType: "BAV/OR",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Param:      "",
				Payload:    "//evil.com",
				Evidence:   "",
				CWE:        "CWE-601",
				Severity:   "Medium",
				PoCType:    "plain",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createPoC(tt.injectType, tt.cwe, tt.severity, tt.req, tt.payload, tt.options)

			if got.Type != tt.want.Type {
				t.Errorf("createPoC() Type = %v, want %v", got.Type, tt.want.Type)
			}
			if got.InjectType != tt.want.InjectType {
				t.Errorf("createPoC() InjectType = %v, want %v", got.InjectType, tt.want.InjectType)
			}
			if got.Method != tt.want.Method {
				t.Errorf("createPoC() Method = %v, want %v", got.Method, tt.want.Method)
			}
			if got.Data != tt.want.Data {
				t.Errorf("createPoC() Data = %v, want %v", got.Data, tt.want.Data)
			}
			if got.Payload != tt.want.Payload {
				t.Errorf("createPoC() Payload = %v, want %v", got.Payload, tt.want.Payload)
			}
			if got.CWE != tt.want.CWE {
				t.Errorf("createPoC() CWE = %v, want %v", got.CWE, tt.want.CWE)
			}
			if got.Severity != tt.want.Severity {
				t.Errorf("createPoC() Severity = %v, want %v", got.Severity, tt.want.Severity)
			}
			if got.PoCType != tt.want.PoCType {
				t.Errorf("createPoC() PoCType = %v, want %v", got.PoCType, tt.want.PoCType)
			}
		})
	}
}

func TestHandlePoC(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/?param=value", nil)

	tests := []struct {
		name    string
		poc     model.PoC
		req     *http.Request
		options model.Options
		showG   bool
	}{
		{
			name: "Basic PoC handling",
			poc: model.PoC{
				Type:       "G",
				InjectType: "XSS",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Payload:    "<script>alert(1)</script>",
				CWE:        "CWE-79",
				Severity:   "High",
				PoCType:    "plain",
			},
			req:     req,
			options: model.Options{},
			showG:   true,
		},
		{
			name: "JSON format PoC handling",
			poc: model.PoC{
				Type:       "G",
				InjectType: "XSS",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Payload:    "<script>alert(1)</script>",
				CWE:        "CWE-79",
				Severity:   "High",
				PoCType:    "plain",
			},
			req: req,
			options: model.Options{
				Format: "json",
			},
			showG: true,
		},
		{
			name: "PoC with OutputRequest",
			poc: model.PoC{
				Type:       "G",
				InjectType: "XSS",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Payload:    "<script>alert(1)</script>",
				CWE:        "CWE-79",
				Severity:   "High",
				PoCType:    "plain",
			},
			req: req,
			options: model.Options{
				OutputRequest: true,
			},
			showG: true,
		},
		{
			name: "PoC with showG false",
			poc: model.PoC{
				Type:       "G",
				InjectType: "XSS",
				Method:     "GET",
				Data:       "https://example.com/?param=value",
				Payload:    "<script>alert(1)</script>",
				CWE:        "CWE-79",
				Severity:   "High",
				PoCType:    "plain",
			},
			req:     req,
			options: model.Options{},
			showG:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is mainly to verify no panics occur
			handlePoC(tt.poc, tt.req, tt.options, tt.showG)
		})
	}
}
