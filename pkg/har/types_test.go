package har

import (
	"testing"
	"time"
)

func TestTime_MarshalJSON(t *testing.T) {
	zeroTime := time.Date(0001, 1, 1, 00, 00, 00, 00, time.UTC)
	tests := []struct {
		name    string
		tr      Time
		want    []byte
		wantErr bool
	}{
		{
			name:    "test",
			tr:      Time(zeroTime),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := Time{}
			_, err := tr.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Time.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		tr      *Time
		args    args
		wantErr bool
	}{
		{
			name: "test",
			tr:   &Time{},
			args: args{
				data: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "test",
			tr:   &Time{},
			args: args{
				data: []byte("oijoij"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Time{}
			if err := tr.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Time.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
