package server

import (
	"reflect"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestGetScan(t *testing.T) {
	type args struct {
		sid     string
		options model.Options
	}
	tests := []struct {
		name string
		args args
		want model.Scan
	}{
		{
			name: "Existing scan",
			args: args{
				sid: "test-scan",
				options: model.Options{
					Scan: map[string]model.Scan{
						"test-scan": {URL: "http://example.com"},
					},
				},
			},
			want: model.Scan{URL: "http://example.com"},
		},
		{
			name: "Non-existing scan",
			args: args{
				sid: "non-existing-scan",
				options: model.Options{
					Scan: map[string]model.Scan{},
				},
			},
			want: model.Scan{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetScan(tt.args.sid, tt.args.options); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetScan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetScans(t *testing.T) {
	tests := []struct {
		name    string
		options model.Options
		want    []string
	}{
		{
			name: "Empty scans",
			options: model.Options{
				Scan: map[string]model.Scan{},
			},
			want: []string{},
		},
		{
			name: "Non-empty scans",
			options: model.Options{
				Scan: map[string]model.Scan{
					"scan1": {},
					"scan2": {},
				},
			},
			want: []string{"scan1", "scan2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetScans(tt.options); !reflect.DeepEqual(len(got), len(tt.want)) {
				t.Errorf("GetScans() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cleanURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "URL with newline",
			args: args{url: "http://example.com\n"},
			want: "http://example.com",
		},
		{
			name: "URL with carriage return",
			args: args{url: "http://example.com\r"},
			want: "http://example.com",
		},
		{
			name: "URL with both newline and carriage return",
			args: args{url: "http://example.com\r\n"},
			want: "http://example.com",
		},
		{
			name: "URL without newline or carriage return",
			args: args{url: "http://example.com"},
			want: "http://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanURL(tt.args.url); got != tt.want {
				t.Errorf("cleanURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
