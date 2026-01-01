package optimization

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestIsOutOfScope(t *testing.T) {
	type args struct {
		options   model.Options
		targetURL string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "exact match - should be out of scope",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com"},
				},
				targetURL: "https://stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "exact match - subdomain should NOT match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com"},
				},
				targetURL: "https://api.stg.hahwul.com/path",
			},
			want: false,
		},
		{
			name: "wildcard match - subdomain should match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"*.stg.hahwul.com"},
				},
				targetURL: "https://api.stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "wildcard match - base domain should NOT match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"*.stg.hahwul.com"},
				},
				targetURL: "https://stg.hahwul.com/path",
			},
			want: false,
		},
		{
			name: "wildcard match - nested subdomain should match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"*.hahwul.com"},
				},
				targetURL: "https://api.stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "non-matching domain - should NOT be out of scope",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com"},
				},
				targetURL: "https://www.hahwul.com/path",
			},
			want: false,
		},
		{
			name: "empty out-of-scope list - should NOT be out of scope",
			args: args{
				options: model.Options{
					OutOfScope: []string{},
				},
				targetURL: "https://stg.hahwul.com/path",
			},
			want: false,
		},
		{
			name: "invalid URL - should be out of scope for safety",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com"},
				},
				targetURL: "://invalid-url",
			},
			want: true,
		},
		{
			name: "case insensitive - should match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"STG.HAHWUL.COM"},
				},
				targetURL: "https://stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "multiple patterns - first matches",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com", "dev.hahwul.com"},
				},
				targetURL: "https://stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "multiple patterns - second matches",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com", "dev.hahwul.com"},
				},
				targetURL: "https://dev.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "scheme-less URL - should match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"stg.hahwul.com"},
				},
				targetURL: "stg.hahwul.com/path",
			},
			want: true,
		},
		{
			name: "scheme-less URL with wildcard - should match",
			args: args{
				options: model.Options{
					OutOfScope: []string{"*.hahwul.com"},
				},
				targetURL: "stg.hahwul.com/path",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOutOfScope(tt.args.options, tt.args.targetURL); got != tt.want {
				t.Errorf("IsOutOfScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_matchDomainPattern(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		pattern string
		want    bool
	}{
		{"exact match", "hahwul.com", "hahwul.com", true},
		{"exact no match", "other.com", "hahwul.com", false},
		{"wildcard matches subdomain", "api.hahwul.com", "*.hahwul.com", true},
		{"wildcard matches nested subdomain", "api.stg.hahwul.com", "*.hahwul.com", true},
		{"wildcard does not match base", "hahwul.com", "*.hahwul.com", false},
		{"partial match should fail", "nothahwul.com", "hahwul.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDomainPattern(tt.host, tt.pattern); got != tt.want {
				t.Errorf("matchDomainPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterOutOfScopeTargets(t *testing.T) {
	tests := []struct {
		name    string
		options model.Options
		targets []string
		want    []string
	}{
		{
			name: "filter out exact match",
			options: model.Options{
				OutOfScope: []string{"stg.hahwul.com"},
			},
			targets: []string{
				"https://www.hahwul.com/path",
				"https://stg.hahwul.com/path",
				"https://dev.hahwul.com/path",
			},
			want: []string{
				"https://www.hahwul.com/path",
				"https://dev.hahwul.com/path",
			},
		},
		{
			name: "filter out wildcard matches",
			options: model.Options{
				OutOfScope: []string{"*.stg.hahwul.com"},
			},
			targets: []string{
				"https://www.hahwul.com/path",
				"https://api.stg.hahwul.com/path",
				"https://stg.hahwul.com/path",
			},
			want: []string{
				"https://www.hahwul.com/path",
				"https://stg.hahwul.com/path",
			},
		},
		{
			name: "empty out-of-scope returns original",
			options: model.Options{
				OutOfScope: []string{},
			},
			targets: []string{
				"https://www.hahwul.com/path",
			},
			want: []string{
				"https://www.hahwul.com/path",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterOutOfScopeTargets(tt.options, tt.targets)
			if len(got) != len(tt.want) {
				t.Errorf("FilterOutOfScopeTargets() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("FilterOutOfScopeTargets()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}
