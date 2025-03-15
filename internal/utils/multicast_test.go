package utils

import (
	"reflect"
	"testing"
)

func TestMakeTargetSlice(t *testing.T) {
	type args struct {
		targets []string
	}
	tests := []struct {
		name string
		args args
		want map[string][]string
	}{
		{
			name: "Single target",
			args: args{
				targets: []string{"http://example.com"},
			},
			want: map[string][]string{
				"example.com": {"http://example.com"},
			},
		},
		{
			name: "Multiple targets with same hostname",
			args: args{
				targets: []string{"http://example.com", "https://example.com/path"},
			},
			want: map[string][]string{
				"example.com": {"http://example.com", "https://example.com/path"},
			},
		},
		{
			name: "Multiple targets with different hostnames",
			args: args{
				targets: []string{"http://example.com", "https://another.com"},
			},
			want: map[string][]string{
				"example.com": {"http://example.com"},
				"another.com": {"https://another.com"},
			},
		},
		{
			name: "Empty targets",
			args: args{
				targets: []string{},
			},
			want: map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MakeTargetSlice(tt.args.targets); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MakeTargetSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
