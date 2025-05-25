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
				// actualParamType not specified, old test case
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Old test cases might not pass without actualParamType, or will use default behavior
			// This is kept for structure, new tests will be more specific.
			if tt.args.ptype == "FORM" { // crude way to map old test to new signature
				_, _ = MakeRequestQuery(tt.args.target, tt.args.param, tt.args.payload, tt.args.ptype, tt.args.pAction, tt.args.pEncode, tt.args.options, model.ParamTypeBodyForm)
			} else {
				_, _ = MakeRequestQuery(tt.args.target, tt.args.param, tt.args.payload, tt.args.ptype, tt.args.pAction, tt.args.pEncode, tt.args.options, model.ParamTypeQuery)
			}
		})
	}
}

func TestMakeRequestQuery_Typed(t *testing.T) {
	tests := []struct {
		name                string
		targetURL           string
		paramName           string
		payloadValue        string
		ptypeString         string // e.g., "inHTML-QUERY"
		pAction             string // "toAppend" or "toReplace"
		pEncode             string // "NaN", "urlEncode", "htmlEncode"
		options             model.Options
		actualParamType     string // model.ParamType*
		expectedURLContains string // Substring to check in final URL
		expectedBody        string // Expected final body string
		expectedHeaders     map[string]string
		expectedContentType string
	}{
		// ParamTypeQuery Tests
		{
			name:                "QUERY_Replace_NoEncode",
			targetURL:           "http://test.com?q=original&other=val",
			paramName:           "q",
			payloadValue:        "<svg onload=alert(1)>",
			ptypeString:         "inHTML-QUERY",
			pAction:             "toReplace",
			pEncode:             "NaN",
			options:             model.Options{},
			actualParamType:     model.ParamTypeQuery,
			expectedURLContains: "q=%3Csvg%20onload=alert(1)%3E&other=val", // Browsers/http library often encodes URL
		},
		{
			name:                "QUERY_Append_URLEncode",
			targetURL:           "http://test.com?q=original",
			paramName:           "q",
			payloadValue:        "&<>'\"",
			ptypeString:         "inHTML-QUERY",
			pAction:             "toAppend",
			pEncode:             "urlEncode",
			options:             model.Options{},
			actualParamType:     model.ParamTypeQuery,
			expectedURLContains: "q=original%26%3C%3E%27%22",
		},
		{
			name:                "QUERY_NewParam_HTMLEncode",
			targetURL:           "http://test.com",
			paramName:           "newq",
			payloadValue:        "<script>",
			ptypeString:         "inHTML-QUERY",
			pAction:             "toReplace", // Action doesn't matter for new param
			pEncode:             "htmlEncode",
			options:             model.Options{},
			actualParamType:     model.ParamTypeQuery,
			expectedURLContains: "newq=%26lt%3Bscript%26gt%3B",
		},

		// ParamTypeHeader Tests
		{
			name:            "HEADER_Replace_NoEncode",
			targetURL:       "http://test.com",
			paramName:       "X-Test-Header",
			payloadValue:    "header<value>",
			ptypeString:     "inHTML-HEADER",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{},
			actualParamType: model.ParamTypeHeader,
			expectedHeaders: map[string]string{"X-Test-Header": "header<value>"},
		},
		{
			name:      "HEADER_Append_URLEncode",
			targetURL: "http://test.com",
			paramName: "X-Another-Header",
			payloadValue: "&foo",
			ptypeString: "inHTML-HEADER",
			pAction:   "toAppend",
			pEncode:   "urlEncode",
			options: model.Options{
				Header: []string{"X-Another-Header: initial"},
			},
			actualParamType: model.ParamTypeHeader,
			expectedHeaders: map[string]string{"X-Another-Header": "initial%26foo"},
		},

		// ParamTypeCookie Tests
		{
			name:            "COOKIE_Replace_NoEncode",
			targetURL:       "http://test.com",
			paramName:       "sessionid",
			payloadValue:    "cookie<value>",
			ptypeString:     "inHTML-COOKIE",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{Cookie: "sessionid=old; other=val"},
			actualParamType: model.ParamTypeCookie,
			expectedHeaders: map[string]string{"Cookie": "sessionid=cookie<value>; other=val"}, // Order might vary
		},
		{
			name:      "COOKIE_Append_URLEncode",
			targetURL: "http://test.com",
			paramName: "pref",
			payloadValue: "&dark",
			ptypeString: "inHTML-COOKIE",
			pAction:   "toAppend",
			pEncode:   "urlEncode",
			options:   model.Options{Cookie: "pref=light; id=1"},
			actualParamType: model.ParamTypeCookie,
			expectedHeaders: map[string]string{"Cookie": "pref=light%26dark; id=1"}, // Order might vary
		},
		{
			name:            "COOKIE_New_NoEncode",
			targetURL:       "http://test.com",
			paramName:       "newcookie",
			payloadValue:    "newval",
			ptypeString:     "inHTML-COOKIE",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{Cookie: "existing=foo"},
			actualParamType: model.ParamTypeCookie,
			expectedHeaders: map[string]string{"Cookie": "existing=foo; newcookie=newval"}, // Order might vary
		},

		// ParamTypeBodyForm Tests
		{
			name:            "BODYFORM_Replace_NoEncode",
			targetURL:       "http://test.com/submit",
			paramName:       "name",
			payloadValue:    "form<val>",
			ptypeString:     "inHTML-BODY_FORM",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{Method: "POST", Data: "name=old&other=data"},
			actualParamType: model.ParamTypeBodyForm,
			expectedBody:    "name=form<val>&other=data", // Order might vary
			expectedContentType: "application/x-www-form-urlencoded",
		},
		{
			name:            "BODYFORM_Append_URLEncode",
			targetURL:       "http://test.com/submit",
			paramName:       "desc",
			payloadValue:    "&more",
			ptypeString:     "inHTML-BODY_FORM",
			pAction:         "toAppend",
			pEncode:         "urlEncode",
			options:         model.Options{Method: "POST", Data: "desc=initial"},
			actualParamType: model.ParamTypeBodyForm,
			expectedBody:    "desc=initial%26more",
			expectedContentType: "application/x-www-form-urlencoded",
		},
		{
			name:            "BODYFORM_NewParam_NoData",
			targetURL:       "http://test.com/submit",
			paramName:       "comment",
			payloadValue:    "a new comment",
			ptypeString:     "inHTML-BODY_FORM",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{Method: "POST"}, // No initial options.Data
			actualParamType: model.ParamTypeBodyForm,
			expectedBody:    "comment=a+new+comment", // Note: url.Values.Encode() replaces space with +
			expectedContentType: "application/x-www-form-urlencoded",
		},
		
		// ParamTypeBodyJSON Tests
		{
			name:            "BODYJSON_Replace_StringValue_NoEncode",
			targetURL:       "http://test.com/api",
			paramName:       "key",
			payloadValue:    "json<value>", // Raw payload
			ptypeString:     "inHTML-BODY_JSON",
			pAction:         "toReplace",
			pEncode:         "NaN", // Payload is used as-is, json.Marshal will escape it for JSON string
			options:         model.Options{Method: "POST", Data: `{"key":"old","other":"val"}`},
			actualParamType: model.ParamTypeBodyJSON,
			expectedBody:    `{"key":"json<value>","other":"val"}`, // json.Marshal escapes < to \u003c, > to \u003e
			expectedContentType: "application/json",
		},
		{
			name:            "BODYJSON_Replace_StringValue_HTMLEncode",
			targetURL:       "http://test.com/api",
			paramName:       "key",
			payloadValue:    "<script>", 
			ptypeString:     "inHTML-BODY_JSON",
			pAction:         "toReplace",
			pEncode:         "htmlEncode", // Payload becomes "&lt;script&gt;"
			options:         model.Options{Method: "POST", Data: `{"key":"old"}`},
			actualParamType: model.ParamTypeBodyJSON,
			expectedBody:    `{"key":"&lt;script&gt;"}`, // json.Marshal escapes & to \u0026, < to \u003c, > to \u003e
			expectedContentType: "application/json",
		},
		{
			name:            "BODYJSON_NewKey_NoEncode",
			targetURL:       "http://test.com/api",
			paramName:       "newKey",
			payloadValue:    "\"hello\"", // Payload is an already JSON-encoded string
			ptypeString:     "inHTML-BODY_JSON",
			pAction:         "toReplace",
			pEncode:         "NaN", 
			options:         model.Options{Method: "POST", Data: `{}`},
			actualParamType: model.ParamTypeBodyJSON,
			expectedBody:    `{"newKey":"\"hello\""}`, // json.Marshal escapes the quotes in the payload
			expectedContentType: "application/json",
		},

		// ParamTypePath Tests (Simplified due to current MakeRequestQuery path logic)
		// Assumes paramName like "path1", "path2" corresponds to segment index (1-based)
		// or direct segment value if MakeRequestQuery is changed to support that.
		// Current MakeRequestQuery path logic is very basic and might need index as string.
		{
			name:                "PATH_Replace_SegmentByIndex_NoEncode",
			targetURL:           "http://test.com/api/v1/data",
			paramName:           "1", // Represents index of "v1" (0-indexed "api", 1-indexed "v1")
			payloadValue:        "v2beta",
			ptypeString:         "inPath-PATH",
			pAction:             "toReplace",
			pEncode:             "NaN",
			options:             model.Options{},
			actualParamType:     model.ParamTypePath,
			expectedURLContains: "/api/v2beta/data", // This is the target path
		},
		{
			name:                "PATH_Replace_SegmentByIndex_URLEncode",
			targetURL:           "http://test.com/user/some profile/view",
			paramName:           "1", // "some profile"
			payloadValue:        "new value",    // Becomes "new%20value"
			ptypeString:         "inPath-PATH",
			pAction:             "toReplace",
			pEncode:             "urlEncode",
			options:             model.Options{},
			actualParamType:     model.ParamTypePath,
			expectedURLContains: "/user/new%20value/view",
		},
		
		// ParamTypeFragment Tests
		{
			name:                "FRAGMENT_Replace_QueryLike_NoEncode",
			targetURL:           "http://test.com/page#token=old&user=test",
			paramName:           "token",
			payloadValue:        "new<token>",
			ptypeString:         "inFragment-FRAGMENT",
			pAction:             "toReplace",
			pEncode:             "NaN",
			options:             model.Options{},
			actualParamType:     model.ParamTypeFragment,
			expectedURLContains: "#token=new%3Ctoken%3E&user=test", // URL encoding applied by URL parser to fragment query
		},
		{
			name:                "FRAGMENT_Append_QueryLike_URLEncode",
			targetURL:           "http://test.com/page#name=initial",
			paramName:           "name",
			payloadValue:        "&appended", // Becomes "%26appended"
			ptypeString:         "inFragment-FRAGMENT",
			pAction:             "toAppend",
			pEncode:             "urlEncode",
			options:             model.Options{},
			actualParamType:     model.ParamTypeFragment,
			expectedURLContains: "#name=initial%26appended",
		},
		/* // Plain fragment replacement is not directly supported by MakeRequestQuery's paramName logic
		   // It assumes query-like structure in fragment if a paramName is given.
		   // To replace the whole fragment, one would typically modify req.URL.Fragment directly.
		{
			name:            "FRAGMENT_Replace_Plain_NoEncode",
			targetURL:       "http://test.com/page#oldFragment",
			paramName:       "fragment_full", // Special name if we want to target whole fragment
			payloadValue:    "new<Fragment>",
			ptypeString:     "inFragment-FRAGMENT",
			pAction:         "toReplace",
			pEncode:         "NaN",
			options:         model.Options{},
			actualParamType: model.ParamTypeFragment,
			expectedURLContains: "#new%3CFragment%3E",
		},
		*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, metadata := MakeRequestQuery(tt.targetURL, tt.paramName, tt.payloadValue, tt.ptypeString, tt.pAction, tt.pEncode, tt.options, tt.actualParamType)
			if req == nil {
				t.Fatalf("MakeRequestQuery returned nil request")
			}

			if tt.expectedURLContains != "" {
				finalURL := req.URL.String()
				// RawQuery might be a better check if specific encoding of query params is important
				// For now, check substring, but be mindful of how Go's URL parser/encoder works
				parsedExpectedURL, _ := url.Parse(tt.targetURL + "?" + tt.expectedURLContains) //簡易的な期待値URLのパース
				expectedQuery := parsedExpectedURL.Query().Encode()
				actualQuery := req.URL.Query().Encode()

				// A more robust check would be to parse both actual and expected queries and compare url.Values
				// This simple check might fail due to parameter order or slight encoding differences by standard library
				// For path, we check the Path component of the URL
				if tt.actualParamType == model.ParamTypePath {
					if !strings.Contains(req.URL.Path, tt.expectedURLContains) {
						t.Errorf("URL Path mismatch for test '%s':\nGot path: %s\nExpected path to contain: %s", tt.name, req.URL.Path, tt.expectedURLContains)
					}
				} else if tt.actualParamType == model.ParamTypeFragment {
					// For fragment, check Fragment component
					// Note: standard URL encoding applies to fragment parts by net/url
					if !strings.Contains(req.URL.Fragment, tt.expectedURLContains) {
                         // To compare fragments like queries, parse them if they are query-like
                        actualFragValues, _ := url.ParseQuery(req.URL.Fragment)
                        expectedFragValues, _ := url.ParseQuery(tt.expectedURLContains)
                        if !reflect.DeepEqual(actualFragValues, expectedFragValues) {
						    t.Errorf("URL Fragment mismatch for test '%s':\nGot fragment: %s\nExpected fragment to contain: %s",tt.name, req.URL.Fragment, tt.expectedURLContains)
                        }
					}
				} else { // For query parameters
					if !strings.Contains(req.URL.RawQuery, tt.expectedURLContains) && actualQuery != expectedQuery {
						// Fallback to check if the query parameters match, regardless of order
						actualValues, _ := url.ParseQuery(req.URL.RawQuery)
						expectedValues, _ := url.ParseQuery(tt.expectedURLContains)
						if !reflect.DeepEqual(actualValues, expectedValues) {
							t.Errorf("URL query mismatch for test '%s':\nGot query: %s\nExpected query part: %s (or equivalent values)", tt.name, req.URL.RawQuery, tt.expectedURLContains)
						}
					}
				}
			}

			if tt.expectedBody != "" {
				body, err := readRequestBody(req)
				if err != nil {
					t.Fatalf("Error reading request body: %v", err)
				}
				// For JSON, exact string match can be tricky due to field ordering.
				// For form data, field ordering can also vary.
				if tt.actualParamType == model.ParamTypeBodyJSON {
					var actualJson, expectedJson map[string]interface{}
					if err := json.Unmarshal([]byte(body), &actualJson); err != nil {
						t.Fatalf("Error unmarshalling actual JSON body: %v\nBody: %s", err, body)
					}
					if err := json.Unmarshal([]byte(tt.expectedBody), &expectedJson); err != nil {
						t.Fatalf("Error unmarshalling expected JSON body: %v\nBody: %s", err, tt.expectedBody)
					}
					if !reflect.DeepEqual(actualJson, expectedJson) {
						t.Errorf("Body JSON mismatch:\nGot:  %s\nWant: %s", body, tt.expectedBody)
					}
				} else if tt.actualParamType == model.ParamTypeBodyForm {
					actualValues, _ := url.ParseQuery(body)
					expectedValues, _ := url.ParseQuery(tt.expectedBody)
					if !reflect.DeepEqual(actualValues, expectedValues) {
						t.Errorf("Body Form mismatch:\nGot:  %s\nWant: %s", body, tt.expectedBody)
					}
				} else {
					if body != tt.expectedBody {
						t.Errorf("Body mismatch:\nGot:  %s\nWant: %s", body, tt.expectedBody)
					}
				}
			}
			
			if tt.expectedContentType != "" {
				if req.Header.Get("Content-Type") != tt.expectedContentType {
					t.Errorf("Content-Type mismatch: Got '%s', want '%s'", req.Header.Get("Content-Type"), tt.expectedContentType)
				}
			}

			for key, val := range tt.expectedHeaders {
				if req.Header.Get(key) != val {
					// Cookie order can be inconsistent, so handle it specially
					if strings.ToLower(key) == "cookie" {
						compareCookies(t, req.Header.Get(key), val)
					} else {
						t.Errorf("Header '%s' mismatch: Got '%s', want '%s'", key, req.Header.Get(key), val)
					}
				}
			}
			
			// Check metadata
			assert.Equal(t, tt.ptypeString, metadata["type"])
			assert.Equal(t, tt.pAction, metadata["action"])
			assert.Equal(t, tt.pEncode, metadata["encode"])
			assert.Equal(t, tt.payloadValue, metadata["payload"]) // original payload
			assert.Equal(t, tt.paramName, metadata["param"])

		})
	}
}

// Helper to compare cookie strings, ignoring order of cookies
func compareCookies(t *testing.T, actualCookieHeader, expectedCookieHeader string) {
	t.Helper()
	parse := func(header string) map[string]string {
		m := make(map[string]string)
		if header == "" {
			return m
		}
		parts := strings.Split(header, ";")
		for _, part := range parts {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 {
				m[kv[0]] = kv[1]
			}
		}
		return m
	}
	actualCookies := parse(actualCookieHeader)
	expectedCookies := parse(expectedCookieHeader)
	if !reflect.DeepEqual(actualCookies, expectedCookies) {
		t.Errorf("Cookie header mismatch:\nActual: %s\nExpected: %s\n(Parsed actual: %v, Parsed expected: %v)", actualCookieHeader, expectedCookieHeader, actualCookies, expectedCookies)
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
