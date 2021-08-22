package optimization

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func Test_CheckUniqParam(t *testing.T) {
	type args struct {
		options model.Options
		k       string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"1234",
						"cat",
					},
				},
				k: "1234",
			},
			want: true,
		},
		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"cat",
						"1234",
					},
				},
				k: "1234",
			},
			want: true,
		},

		{
			name: "test - true",
			args: args{
				options: model.Options{
					UniqParam: []string{},
				},
				k: "5555",
			},
			want: true,
		},
		{
			name: "test - false",
			args: args{
				options: model.Options{
					UniqParam: []string{
						"1234",
						"cat",
					},
				},
				k: "5555",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckUniqParam(tt.args.options, tt.args.k); got != tt.want {
				t.Errorf("checkUniqParam() = %v, want %v", got, tt.want)
			}
		})
	}
}
