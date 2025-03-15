package optimization

import (
	"reflect"
	"testing"

	model "github.com/hahwul/dalfox/v2/pkg/model"
)

func TestSetPayloadValue(t *testing.T) {
	type args struct {
		payloads []string
		options  model.Options
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "none",
			args: args{
				payloads: []string{"1"},
				options: model.Options{
					CustomAlertType: "none",
				},
			},
			want: []string{"1"},
		},
		{
			name: "str",
			args: args{
				payloads: []string{"1"},
				options: model.Options{
					CustomAlertType: "str",
				},
			},
			want: []string{"1", "1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SetPayloadValue(tt.args.payloads, tt.args.options); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetPayloadValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
