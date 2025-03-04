package scanning

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestSetP(t *testing.T) {
	type args struct {
		p       url.Values
		dp      url.Values
		name    string
		options model.Options
	}
	tests := []struct {
		name   string
		args   args
		want   url.Values
		wantDp url.Values
	}{
		{
			name: "Set parameter",
			args: args{
				p:       url.Values{},
				dp:      url.Values{},
				name:    "test",
				options: model.Options{},
			},
			want:   url.Values{"test": []string{""}},
			wantDp: url.Values{},
		},
		{
			name: "Set data parameter",
			args: args{
				p:       url.Values{},
				dp:      url.Values{},
				name:    "test",
				options: model.Options{Data: "data"},
			},
			want:   url.Values{"test": []string{""}},
			wantDp: url.Values{"test": []string{""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotDp := setP(tt.args.p, tt.args.dp, tt.args.name, tt.args.options)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("setP() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(gotDp, tt.wantDp) {
				t.Errorf("setP() gotDp = %v, want %v", gotDp, tt.wantDp)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	type args struct {
		target string
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantP   url.Values
		wantDp  url.Values
		wantErr bool
	}{
		{
			name: "Valid URL",
			args: args{
				target: "http://example.com",
			},
			want: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
			wantP:   url.Values{},
			wantDp:  url.Values{},
			wantErr: false,
		},
		{
			name: "Invalid URL",
			args: args{
				target: "://example.com",
			},
			want:    nil,
			wantP:   nil,
			wantDp:  nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotP, gotDp, err := parseURL(tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseURL() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("parseURL() gotP = %v, want %v", gotP, tt.wantP)
			}
			if !reflect.DeepEqual(gotDp, tt.wantDp) {
				t.Errorf("parseURL() gotDp = %v, want %v", gotDp, tt.wantDp)
			}
		})
	}
}
