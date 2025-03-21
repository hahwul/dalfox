package optimization

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func TestGenerateNewRequest(t *testing.T) {
	type args struct {
		url     string
		payload string
		options model.Options
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test - normal",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{},
			},
			want: true,
		},
		{
			name: "test - data",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{
					Data:   "a=1",
					Method: "POST",
				},
			},
			want: true,
		},
		{
			name: "test - header",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{
					Header: []string{"Cookie: 1234", "Auth: 12344"},
				},
			},
			want: true,
		},
		{
			name: "test - cookie",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{
					Cookie: "a=1",
				},
			},
			want: true,
		},
		{
			name: "test - ua",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{
					UserAgent: "abcd",
				},
			},
			want: true,
		},
		{
			name: "test - cookiefromraw",
			args: args{
				url:     "https://www.hahwul.com?q=1",
				payload: "dalfox",
				options: model.Options{
					CookieFromRaw: "",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateNewRequest(tt.args.url, tt.args.payload, tt.args.options); !reflect.DeepEqual((got != nil), tt.want) {
				t.Errorf("GenerateNewRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRawCookie(t *testing.T) {
	type args struct {
		cookies []*http.Cookie
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test - nil",
			args: args{},
			want: "",
		},
		{
			name: "test - nil",
			args: args{
				cookies: []*http.Cookie{
					&http.Cookie{
						Name:     "test",
						Value:    "1234",
						HttpOnly: true,
					},
				},
			},
			want: "test=1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRawCookie(tt.args.cookies); got != tt.want {
				t.Errorf("GetRawCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMakeHeaderQuery(t *testing.T) {
	type args struct {
		target  string
		hn      string
		hv      string
		options model.Options
	}
	tests := []struct {
		name  string
		args  args
		want  *http.Request
		want1 map[string]string
	}{
		{
			name: "TestMakeHeaderQuery1",
			args: args{
				target: "https://www.hahwul.com",
				hn:     "param",
				hv:     "test",
				options: model.Options{
					Data:   "abcd=1234",
					Cookie: "abcd=1234",
					Header: []string{
						"X-API-Key: 1234",
					},
					Method: "POST",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = MakeHeaderQuery(tt.args.target, tt.args.hn, tt.args.hv, tt.args.options)
		})
	}
}

func TestMakeRequestQuery(t *testing.T) {
	type args struct {
		target  string
		param   string
		payload string
		ptype   string
		pAction string
		pEncode string
		options model.Options
	}
	tests := []struct {
		name  string
		args  args
		want  *http.Request
		want1 map[string]string
	}{
		{
			name: "TestMakeRequestQuery1",
			args: args{
				target:  "https://www.hahwul.com",
				param:   "param",
				payload: "dalfox",
				ptype:   "",
				pAction: "",
				pEncode: "htmlEncode",
				options: model.Options{
					Data:   "abcd=1234",
					Cookie: "abcd=1234",
					Header: []string{
						"X-API-Key: 1234",
					},
					Method: "POST",
				},
			},
		},
		{
			name: "TestMakeRequestQuery2",
			args: args{
				target:  "https://www.hahwul.com",
				param:   "param",
				payload: "dalfox",
				ptype:   "FORM",
				pAction: "toAppend",
				pEncode: "urlEncode",
				options: model.Options{
					Data:   "abcd=1234",
					Cookie: "abcd=1234",
					Header: []string{
						"X-API-Key: 1234",
					},
					Method: "POST",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = MakeRequestQuery(tt.args.target, tt.args.param, tt.args.payload, tt.args.ptype, tt.args.pAction, tt.args.pEncode, tt.args.options)
		})
	}
}

func TestOptimization(t *testing.T) {
	type args struct {
		payload  string
		badchars []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test - true",
			args: args{
				payload:  "asdf",
				badchars: []string{"!", "@"},
			},
			want: true,
		},
		{
			name: "test - false",
			args: args{
				payload:  "abcd!asdf",
				badchars: []string{"!", "@"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Optimization(tt.args.payload, tt.args.badchars); got != tt.want {
				t.Errorf("Optimization() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUrlEncode(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name       string
		args       args
		wantResult string
	}{
		{
			name: "test - single",
			args: args{
				s: "a",
			},
			wantResult: "%61",
		},
		/*
			{
				name: "test - quaternary",
				args: args{
					s: fmt.Sprintf("%c", 0x2fffff),
				},
				wantResult: "",
			},
		*/
		{
			name: "test - triple",
			args: args{
				s: "환",
			},
			wantResult: "%ED%99%98",
		},
		{
			name: "test - double",
			args: args{
				s: "Ǳ",
			},
			wantResult: "%C7%B1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := UrlEncode(tt.args.s); gotResult != tt.wantResult {
				t.Errorf("UrlEncode() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
