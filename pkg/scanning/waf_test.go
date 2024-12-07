package scanning

import (
	"net/http"
	"testing"
)

func Test_checkWAF(t *testing.T) {
	type args struct {
		header http.Header
		body   string
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 string
	}{
		{
			name: "Match 360 Web Application Firewall",
			args: args{
				header: http.Header{"X-Powered-By-360wzb": []string{"value"}},
				body:   "some body content",
			},
			want:  true,
			want1: "360 Web Application Firewall (360)",
		},
		{
			name: "Match aeSecure",
			args: args{
				header: http.Header{"aeSecure-code": []string{"value"}},
				body:   "aesecure_denied.png",
			},
			want:  true,
			want1: "aeSecure",
		},
		{
			name: "Match CloudFlare Web Application Firewall",
			args: args{
				header: http.Header{"cf-ray": []string{"value"}},
				body:   "Attention Required!",
			},
			want:  true,
			want1: "CloudFlare Web Application Firewall (CloudFlare)",
		},
		{
			name: "No match",
			args: args{
				header: http.Header{"Some-Header": []string{"value"}},
				body:   "some body content",
			},
			want:  false,
			want1: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := checkWAF(tt.args.header, tt.args.body)
			if got != tt.want {
				t.Errorf("checkWAF() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("checkWAF() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
