package scanning

import "testing"

func Test_checkVStatus(t *testing.T) {
	type args struct {
		vStatus map[string]bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "All true values",
			args: args{
				vStatus: map[string]bool{
					"status1": true,
					"status2": true,
				},
			},
			want: true,
		},
		{
			name: "Contains false value",
			args: args{
				vStatus: map[string]bool{
					"status1": true,
					"status2": false,
				},
			},
			want: false,
		},
		{
			name: "Special key with false value",
			args: args{
				vStatus: map[string]bool{
					"pleasedonthaveanamelikethis_plz_plz": false,
				},
			},
			want: false,
		},
		{
			name: "Special key with true value",
			args: args{
				vStatus: map[string]bool{
					"pleasedonthaveanamelikethis_plz_plz": true,
				},
			},
			want: false,
		},
		{
			name: "Empty map",
			args: args{
				vStatus: map[string]bool{},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkVStatus(tt.args.vStatus); got != tt.want {
				t.Errorf("checkVStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
