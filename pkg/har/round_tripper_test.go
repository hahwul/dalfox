// Package har implements HAR file output support for Dalfox
package har

import (
	"net/http"
	"reflect"
	"testing"
	"time"
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
	cookies := []*http.Cookie{
		{
			Name:     "a",
			Value:    "a",
			Path:     "/",
			Domain:   "hahwul.com",
			Expires:  time.Time{},
			HttpOnly: false,
			Secure:   false,
		},
	}

	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "test",
			args: args{
				cookies: cookies,
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(toHARCookies(tt.args.cookies)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toHARCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}
