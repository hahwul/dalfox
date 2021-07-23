package printing

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestBanner(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "run",
			args: args{
				options: model.Options{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Banner(tt.args.options)
		})
	}
}
