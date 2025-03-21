package payload

import (
	"testing"
)

func TestGenerateBulkPayload(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Test case 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GenerateBulkPayload()
			if len(got) <= 0 {
				t.Errorf("GenerateBulkPayload() got = %v", got)
			}
			if got1 <= 0 {
				t.Errorf("GenerateBulkPayload() got1 = %v", got1)
			}
		})
	}
}
