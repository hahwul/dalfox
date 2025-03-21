package scanning

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func Test_foundAction(t *testing.T) {
	type args struct {
		options model.Options
		target  string
		query   string
		ptype   string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Basic command substitution",
			args: args{
				options: model.Options{
					FoundAction:      "echo '@@target@@ @@query@@ @@type@@'",
					FoundActionShell: "sh",
				},
				target: "https://example.com",
				query:  "xss",
				ptype:  "reflected",
			},
		},
		{
			name: "Empty command",
			args: args{
				options: model.Options{
					FoundAction:      "",
					FoundActionShell: "sh",
				},
				target: "https://example.com",
				query:  "xss",
				ptype:  "stored",
			},
		},
		{
			name: "Multiple replacements of same variable",
			args: args{
				options: model.Options{
					FoundAction:      "echo '@@target@@ @@target@@ @@query@@ @@type@@'",
					FoundActionShell: "sh",
				},
				target: "https://example.com",
				query:  "xss",
				ptype:  "dom",
			},
		},
		{
			name: "Custom shell",
			args: args{
				options: model.Options{
					FoundAction:      "echo $0",
					FoundActionShell: "bash",
				},
				target: "https://example.com",
				query:  "xss",
				ptype:  "reflected",
			},
		},
		{
			name: "No variables in command",
			args: args{
				options: model.Options{
					FoundAction:      "echo 'test'",
					FoundActionShell: "sh",
				},
				target: "https://example.com",
				query:  "xss",
				ptype:  "stored",
			},
		},
	}

	// This is primarily a smoke test to ensure the function doesn't panic or error out
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can only test that the function executes without panicking
			// since it doesn't return any values and executes shell commands
			foundAction(tt.args.options, tt.args.target, tt.args.query, tt.args.ptype)
		})
	}
}
