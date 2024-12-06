package scanning

import "testing"

func Test_checkCSP(t *testing.T) {
	type args struct {
		policy string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Contains google.com",
			args: args{policy: "default-src 'self'; script-src 'self' *.google.com;"},
			want: "*.google.com\n    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1",
		},
		{
			name: "Contains multiple domains",
			args: args{policy: "default-src 'self'; script-src 'self' *.google.com *.yahoo.com;"},
			want: "*.google.com *.yahoo.com\n    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1",
		},
		{
			name: "No matching domains",
			args: args{policy: "default-src 'self'; script-src 'self';"},
			want: "",
		},
		{
			name: "Contains yandex.net",
			args: args{policy: "default-src 'self'; script-src 'self' *.yandex.net;"},
			want: "*.yandex.net\n    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1",
		},
		{
			name: "Contains multiple domains with different formats",
			args: args{policy: "default-src 'self'; script-src 'self' *.google.com api.vk.com;"},
			want: "*.google.com api.vk.com\n    Needs manual testing. please refer to it. https://t.co/lElLxtainw?amp=1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkCSP(tt.args.policy); got != tt.want {
				t.Errorf("checkCSP() = %v, want %v", got, tt.want)
			}
		})
	}
}
