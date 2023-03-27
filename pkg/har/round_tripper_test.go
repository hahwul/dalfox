// Package har implements HAR file output support for Dalfox
package har

import (
	"net/http"
	"reflect"
	"testing"
)

func Test_toHARNVP(t *testing.T) {
	type args struct {
		vs map[string][]string
	}
	tests := []struct {
		name string
		args args
		want []*NVP
	}{
		{
			name: "empty",
			args: args{
				vs: map[string][]string{},
			},
			want: []*NVP{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toHARNVP(tt.args.vs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toHARNVP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toHARCookies(t *testing.T) {
	type args struct {
		cookies []*http.Cookie
	}
	tests := []struct {
		name string
		args args
		want []*Cookie
	}{
		{
			name: "test",
			args: args{},
			want: []*Cookie{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toHARCookies(tt.args.cookies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toHARCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}
