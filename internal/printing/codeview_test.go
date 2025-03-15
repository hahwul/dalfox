package printing

import (
	"testing"
)

func TestCodeView(t *testing.T) {
	type args struct {
		resbody string
		pattern string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test with pattern",
			args: args{
				resbody: "This is a test string.\nAnother line with pattern.\nEnd of test.",
				pattern: "pattern",
			},
			want: "2 line:  Another line with pattern.",
		},
		{
			name: "test without pattern",
			args: args{
				resbody: "This is a test string.\nAnother line.\nEnd of test.",
				pattern: "pattern",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CodeView(tt.args.resbody, tt.args.pattern); got != tt.want {
				t.Errorf("CodeView() = %v, want %v", got, tt.want)
			}
		})
	}
}
