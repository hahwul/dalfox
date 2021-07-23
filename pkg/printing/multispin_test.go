package printing

import (
	"testing"
	"time"

	spinner "github.com/briandowns/spinner"
)

func TestDrawSpinner(t *testing.T) {
	type args struct {
		s       *spinner.Spinner
		t       map[string]int
		pointer int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test",
			args: args{
				s: spinner.New(spinner.CharSets[9], 100*time.Millisecond),
				t: map[string]int{
					"a": 1,
				},
				pointer: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DrawSpinner(tt.args.s, tt.args.t, tt.args.pointer)
		})
	}
}
