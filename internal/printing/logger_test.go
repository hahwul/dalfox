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

func Test_SetSpinner(t *testing.T) {
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
			SetSpinner(tt.args.str, tt.args.options)
		})
	}
}

func Test_RestartSpinner(t *testing.T) {
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
			RestartSpinner(tt.args.options)
		})
	}
}

func Test_StopSpinner(t *testing.T) {
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
			StopSpinner(tt.args.options)
		})
	}
}

func TestSummary(t *testing.T) {
	type args struct {
		options model.Options
		target  string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test - silence",
			args: args{
				options: model.Options{
					Silence:        true,
					MiningWordlist: "",
					BlindURL:       "",
				},
				target: "",
			},
		},
		{
			name: "test - no silence",
			args: args{
				options: model.Options{
					Silence: false,
				},
				target: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Summary(tt.args.options, tt.args.target)
		})
	}
}

func TestDalLog(t *testing.T) {
	type args struct {
		level   string
		text    string
		options model.Options
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test - DEBUG",
			args: args{
				level: "DEBUG",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - INFO",
			args: args{
				level: "INFO",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - WEAK",
			args: args{
				level: "WEAK",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - VULN",
			args: args{
				level: "VULN",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - SYSTEM",
			args: args{
				level: "SYSTEM",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - SYSTEM",
			args: args{
				level: "SYSTEM",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					NoSpinner:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - SYSTEM-M",
			args: args{
				level: "SYSTEM-M",
				text:  "",
				options: model.Options{
					Debug:         true,
					OutputAll:     true,
					MulticastMode: true,
					Silence:       true,
					IsLibrary:     true,
					AuroraObject:  aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - GREP",
			args: args{
				level: "GREP",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - CODE",
			args: args{
				level: "CODE",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - YELLOW",
			args: args{
				level: "YELLOW",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - ERRROR",
			args: args{
				level: "ERROR",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					IsLibrary:    true,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - PRINT",
			args: args{
				level: "PRINT",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					Silence:      true,
					IsLibrary:    false,
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - PRINT",
			args: args{
				level: "PRINT",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					Silence:      true,
					IsLibrary:    false,
					OutputFile:   "/dev/null/dalfox-test",
					Format:       "json",
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
		{
			name: "test - FTEXT",
			args: args{
				level: "INFO",
				text:  "",
				options: model.Options{
					Debug:        true,
					OutputAll:    true,
					Silence:      true,
					IsLibrary:    false,
					OutputFile:   "/dev/null/dalfox-test",
					Format:       "json",
					AuroraObject: aurora.NewAurora(true),
					ScanResult: model.Result{
						Logs: []string{""},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DalLog(tt.args.level, tt.args.text, tt.args.options)
		})
	}
}
