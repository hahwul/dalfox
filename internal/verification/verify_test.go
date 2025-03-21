package verification

import "testing"

func TestVerifyReflectionWithLine(t *testing.T) {
	type args struct {
		body    string
		payload string
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 int
	}{
		{
			name: "true-1",
			args: args{
				body:    "adff\ndalfox\n1234",
				payload: "dalfox",
			},
			want:  true,
			want1: 2,
		},
		{
			name: "false-1",
			args: args{
				body:    "adff\111\n1234",
				payload: "dalfox",
			},
			want:  false,
			want1: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := VerifyReflectionWithLine(tt.args.body, tt.args.payload)
			if got != tt.want {
				t.Errorf("VerifyReflectionWithLine() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("VerifyReflectionWithLine() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestVerifyReflection(t *testing.T) {
	type args struct {
		body    string
		payload string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "true",
			args: args{
				body:    "1234dalfox1234",
				payload: "dalfox",
			},
			want: true,
		},
		{
			name: "false",
			args: args{
				body:    "987879788",
				payload: "dalfox",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyReflection(tt.args.body, tt.args.payload); got != tt.want {
				t.Errorf("VerifyReflection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyDOM(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "true-class",
			args: args{
				s: "<div class=\"dalfox\">ab</div>",
			},
			want: true,
		},
		{
			name: "true-id",
			args: args{
				s: "<div id=dalfox>ab</div>",
			},
			want: true,
		},
		{
			name: "false",
			args: args{
				s: "<div>dalfox</div>",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyDOM(tt.args.s); got != tt.want {
				t.Errorf("VerifyDOM() = %v, want %v", got, tt.want)
			}
		})
	}
}
