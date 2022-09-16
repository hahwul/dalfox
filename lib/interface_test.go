package lib

import (
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestResult_IsFound(t *testing.T) {
	type fields struct {
		Logs      []string
		PoCs      []model.PoC
		Params    []model.ParamResult
		Duration  time.Duration
		StartTime time.Time
		EndTime   time.Time
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "test true",
			fields: fields{
				PoCs: []model.PoC{
					model.PoC{
						Type:   "test",
						Method: "GET",
						Data:   "[V] testcode",
					},
				},
			},
			want: true,
		},
		{
			name: "test false",
			fields: fields{
				PoCs: []model.PoC{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Result{
				Logs:      tt.fields.Logs,
				PoCs:      tt.fields.PoCs,
				Duration:  tt.fields.Duration,
				StartTime: tt.fields.StartTime,
				EndTime:   tt.fields.EndTime,
			}
			if got := c.IsFound(); got != tt.want {
				t.Errorf("Result.IsFound() = %v, want %v", got, tt.want)
			}
		})
	}
}
