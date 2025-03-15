package utils

import "testing"

func TestGenerateRandomToken(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
	}{
		{name: "Test case 1", args: args{url: "http://example.com"}},
		{name: "Test case 2", args: args{url: "http://example.org"}},
		{name: "Test case 3", args: args{url: "http://example.net"}},
		{name: "Test case 4", args: args{url: "http://example.edu"}},
		{name: "Test case 5", args: args{url: "http://example.gov"}},
	}
	tokens := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateRandomToken(tt.args.url)
			if _, exists := tokens[got]; exists {
				t.Errorf("GenerateRandomToken() generated a duplicate token: %v", got)
			}
			tokens[got] = true
		})
	}
}
