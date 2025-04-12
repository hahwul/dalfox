package server

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestRunMCPServer(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test with default options",
			args: args{
				options: model.Options{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RunMCPServer(tt.args.options)
		})
	}
}

func Test_generateScanID(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test with valid URL",
			args: args{
				url: "http://example.com",
			},
			want: "mcp-http-example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateScanID(tt.args.url); got != tt.want {
				t.Errorf("generateScanID() = %v, want %v", got, tt.want)
			}
		})
	}
}
