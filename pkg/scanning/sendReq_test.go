package scanning

import (
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
