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
