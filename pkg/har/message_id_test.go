package har

import "testing"

func TestNewMessageID(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Test case 1",
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewMessageID(); got != nil {
				t.Errorf("NewMessageID() = %v, got)
			}
		})
	}
}
