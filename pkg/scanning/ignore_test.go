package scanning

import "testing"

func Test_isAllowType(t *testing.T) {
	type args struct {
		contentType string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Allowed type - text/html",
			args: args{
				contentType: "text/html",
			},
			want: true,
		},
		{
			name: "Not allowed type - application/json",
			args: args{
				contentType: "application/json",
			},
			want: false,
		},
		{
			name: "Not allowed type - text/javascript",
			args: args{
				contentType: "text/javascript",
			},
			want: false,
		},
		{
			name: "Allowed type with charset - text/html; charset=UTF-8",
			args: args{
				contentType: "text/html; charset=UTF-8",
			},
			want: true,
		},
		{
			name: "Not allowed type with charset - application/json; charset=UTF-8",
			args: args{
				contentType: "application/json; charset=UTF-8",
			},
			want: false,
		},
		{
			name: "Allowed type - application/xml",
			args: args{
				contentType: "application/xml",
			},
			want: true,
		},
		{
			name: "Not allowed type - image/jpeg",
			args: args{
				contentType: "image/jpeg",
			},
			want: false,
		},
		{
			name: "Not allowed type - image/png",
			args: args{
				contentType: "image/png",
			},
			want: false,
		},
		{
			name: "Not allowed type - text/plain",
			args: args{
				contentType: "text/plain",
			},
			want: false,
		},
		{
			name: "Not allowed type - text/css",
			args: args{
				contentType: "text/css",
			},
			want: false,
		},
		{
			name: "Not allowed type - application/rss+xml",
			args: args{
				contentType: "application/rss+xml",
			},
			want: false,
		},
		{
			name: "Allowed type - text/xml",
			args: args{
				contentType: "text/xml",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowType(tt.args.contentType); got != tt.want {
				t.Errorf("isAllowType() = %v, want %v", got, tt.want)
			}
		})
	}
}
