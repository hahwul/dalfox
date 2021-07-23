package printing

import (
	"strconv"
	"testing"
	"time"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/pkg/model"
	aurora "github.com/logrusorgru/aurora"
)

func Test_boolToColorStr(t *testing.T) {
	type args struct {
		b       bool
		options model.Options
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "false",
			args: args{
				b: false,
				options: model.Options{
					AuroraObject: aurora.NewAurora(false),
				},
			},
			want: "false",
		},
		{
			name: "true",
			args: args{
				b: true,
				options: model.Options{
					AuroraObject: aurora.NewAurora(true),
				},
			},
			want: aurora.BrightGreen(strconv.FormatBool(true)).String(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boolToColorStr(tt.args.b, tt.args.options); got != tt.want {
				t.Errorf("boolToColorStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setSpinner(t *testing.T) {
	type args struct {
		str     string
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no SpinnerObject",
			args: args{
				str:     "",
				options: model.Options{},
			},
		},
		{
			name: "SpinnerObject",
			args: args{
				str: "",
				options: model.Options{
					SpinnerObject: spinner.New(spinner.CharSets[9], 100*time.Millisecond),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSpinner(tt.args.str, tt.args.options)
		})
	}
}

func Test_restartSpinner(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no SpinnerObject",
			args: args{
				options: model.Options{},
			},
		},
		{
			name: "SpinnerObject",
			args: args{
				options: model.Options{
					SpinnerObject: spinner.New(spinner.CharSets[9], 100*time.Millisecond),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restartSpinner(tt.args.options)
		})
	}
}

func Test_stopSpinner(t *testing.T) {
	type args struct {
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "no SpinnerObject",
			args: args{
				options: model.Options{},
			},
		},
		{
			name: "SpinnerObject",
			args: args{
				options: model.Options{
					SpinnerObject: spinner.New(spinner.CharSets[9], 100*time.Millisecond),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopSpinner(tt.args.options)
		})
	}
}
