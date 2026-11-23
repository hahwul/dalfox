package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

func Test_checkHost(t *testing.T) {
	opts := &model.Options{ServerHost: "dalfox.bind", AllowedHosts: []string{"dalfox.internal"}}
	cases := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:6664", true},
		{"10.0.0.5:6664", true},
		{"[::1]:6664", true},
		{"localhost:6664", true},
		{"LOCALHOST", true},
		{"dalfox.bind:6664", true},
		{"dalfox.internal:6664", true},
		{"", true},
		{"evil.example:6664", false},
		{"evil.example", false},
		{"localhost.evil.example", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/scans", nil)
		req.Host = tc.host
		got := checkHost(req, opts)
		assert.Equal(t, tc.ok, got == "", "host %q: %q", tc.host, got)
	}
}

func Test_checkCrossSite(t *testing.T) {
	opts := &model.Options{AllowedOrigins: []string{"http://ui.local:3000"}}
	cases := []struct {
		name    string
		headers map[string]string
		ok      bool
	}{
		{"non-browser client", nil, true},
		{"allowed origin", map[string]string{"Origin": "http://ui.local:3000", "Sec-Fetch-Site": "cross-site"}, true},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, false},
		{"null origin", map[string]string{"Origin": "null"}, false},
		{"img/script without origin", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"same-site subdomain", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"typed URL", map[string]string{"Sec-Fetch-Site": "none"}, true},
		{"same origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		got := checkCrossSite(req, opts, newOriginMatcher(opts.AllowedOrigins))
		assert.Equal(t, tc.ok, got == "", "%s: %q", tc.name, got)
	}

	// --jsonp exists to be read cross-origin, so it opts out.
	req := httptest.NewRequest(http.MethodGet, "/scan/x", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	assert.Empty(t, checkCrossSite(req, &model.Options{JSONP: true}, originMatcher{}))
}

func Test_checkCrossSite_sameOrigin(t *testing.T) {
	// The bundled Swagger UI sends Origin on its POST/DELETE calls.
	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req.Host = "127.0.0.1:6664"
	req.Header.Set("Origin", "http://127.0.0.1:6664")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	assert.Empty(t, checkCrossSite(req, &model.Options{}, originMatcher{}))

	// Same host, different port is another origin.
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	assert.NotEmpty(t, checkCrossSite(req, &model.Options{}, originMatcher{}))
	req.Header.Set("Origin", "null")
	assert.NotEmpty(t, checkCrossSite(req, &model.Options{}, originMatcher{}))
}

func Test_originMatcher_matchesEchoCORS(t *testing.T) {
	m := newOriginMatcher([]string{"https://*.corp.example", "http://ui.local:300?", "https://exact.example/"})
	assert.True(t, m.allows("https://ui.corp.example"))
	assert.True(t, m.allows("https://a.b.corp.example"))
	assert.True(t, m.allows("http://ui.local:3001"))
	// echo CORS does not strip a trailing slash, so neither do we.
	assert.False(t, m.allows("https://exact.example"))
	assert.True(t, m.allows("https://exact.example/"))
	assert.False(t, m.allows("https://corp.example.evil"))
	assert.False(t, m.allows("https://evilcorp.example"))
	assert.False(t, m.allows("http://ui.local:30011"))
	assert.True(t, newOriginMatcher([]string{"*"}).allows("https://anything.example"))
	assert.False(t, newOriginMatcher(nil).allows("https://anything.example"))
}

// stubScans replaces the scan launcher for the duration of a test, so no
// real scan goroutine outlives it.
func stubScans(t *testing.T) chan model.Options {
	t.Helper()
	got := make(chan model.Options, 16)
	orig := startAPIScan
	startAPIScan = func(_ string, rq model.Options, _ model.Options, _ string) { got <- rq }
	t.Cleanup(func() { startAPIScan = orig })
	return got
}

func serve(e *echo.Echo, method, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:6664"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

const scanBody = `{"url":"http://127.0.0.1:1/"}`

func Test_requestSourceGuard_onServer(t *testing.T) {
	stubScans(t)
	scans := []string{}
	options := model.Options{ServerHost: "127.0.0.1", Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)

	rec := serve(e, http.MethodPost, "/scan", scanBody, nil)
	assert.Equal(t, http.StatusOK, rec.Code, "curl-style client must keep working")

	rec = serve(e, http.MethodPost, "/scan", scanBody, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Origin: https://evil.example")

	rec = serve(e, http.MethodPost, "/scan", scanBody, func(r *http.Request) { r.Host = "rebind.evil.example:6664" })
	assert.Equal(t, http.StatusForbidden, rec.Code, "DNS-rebound Host must be rejected")
	assert.Contains(t, rec.Body.String(), "untrusted Host")

	// /health is browser-probeable too; the guard covers every route.
	rec = serve(e, http.MethodGet, "/health", "", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Sec-Fetch-Site: cross-site")

	// Same-origin Swagger UI calls carry an Origin and must pass.
	rec = serve(e, http.MethodDelete, "/scans/all", "", func(r *http.Request) {
		r.Header.Set("Origin", "http://127.0.0.1:6664")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	assert.Equal(t, http.StatusOK, rec.Code)
}

func Test_requestSourceGuard_preflightGetsHostCheck(t *testing.T) {
	scans := []string{}
	options := model.Options{ServerHost: "127.0.0.1", AllowedOrigins: []string{"https://*.example.com"}, Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)
	preflight := func(host string) int {
		return serve(e, http.MethodOptions, "/scan", "", func(r *http.Request) {
			r.Host = host
			r.Header.Set("Origin", "https://app.example.com")
			r.Header.Set("Access-Control-Request-Method", "POST")
		}).Code
	}
	assert.Equal(t, http.StatusForbidden, preflight("rebind.evil.example:6664"))
	rec := serve(e, http.MethodOptions, "/scan", "", func(r *http.Request) {
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Access-Control-Request-Method", "POST")
	})
	assert.Equal(t, http.StatusNoContent, rec.Code)
	// echo answers 204 even for a rejected origin; the header is what counts.
	assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
}

func Test_jsonpOptsOutReadsOnly(t *testing.T) {
	stubScans(t)
	scans := []string{}
	options := model.Options{ServerHost: "127.0.0.1", JSONP: true, Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)
	crossSite := func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}
	assert.Equal(t, http.StatusForbidden, serve(e, http.MethodPost, "/scan", scanBody, crossSite).Code)
	assert.Equal(t, http.StatusForbidden, serve(e, http.MethodDelete, "/scans/all", "", crossSite).Code)
	rec := serve(e, http.MethodGet, "/health?callback=cb", "", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
	assert.Equal(t, http.StatusOK, rec.Code, "<script src> reads are what --jsonp is for")
	assert.True(t, strings.HasPrefix(rec.Body.String(), "cb("), rec.Body.String())
	rec = serve(e, http.MethodGet, "/health?callback=cb", "", func(r *http.Request) { r.Host = "rebind.evil.example:6664" })
	assert.Equal(t, http.StatusForbidden, rec.Code, "--jsonp keeps the Host check")
}

func Test_apiKeyServer_skipsSourceGuard(t *testing.T) {
	stubScans(t)
	scans := []string{}
	options := model.Options{ServerHost: "0.0.0.0", APIKey: "k", Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)
	byServiceName := func(r *http.Request) { r.Host = "dalfox:6664" }
	assert.Equal(t, http.StatusUnauthorized, serve(e, http.MethodGet, "/health", "", byServiceName).Code)
	assert.Equal(t, http.StatusOK, serve(e, http.MethodGet, "/health", "", func(r *http.Request) {
		byServiceName(r)
		r.Header.Set(APIKeyHeader, "k")
	}).Code, "a keyed client addressing a compose/k8s service name must work")
}

func Test_setupEchoServer_enforcesKeyWhateverServerType(t *testing.T) {
	// --type REST / library callers with an empty ServerType used to skip the
	// API key check entirely.
	for _, st := range []string{"", "REST", "rest", "anything"} {
		scans := []string{}
		options := model.Options{ServerType: st, APIKey: "k", Scan: map[string]model.Scan{}}
		e := setupEchoServer(&options, &scans)
		assert.Equal(t, http.StatusUnauthorized, serve(e, http.MethodGet, "/health", "", nil).Code, "ServerType %q", st)
		assert.Equal(t, http.StatusOK, serve(e, http.MethodGet, "/health", "", func(r *http.Request) { r.Header.Set(APIKeyHeader, "k") }).Code, "ServerType %q", st)
	}
}

func Test_postScanHandler_contentType(t *testing.T) {
	stubScans(t)
	scans := []string{}
	options := model.Options{ServerHost: "127.0.0.1", Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)
	for ct, want := range map[string]int{
		"application/json":                  http.StatusOK,
		"application/json; charset=utf-8":   http.StatusOK,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType,
		"text/plain":                        http.StatusUnsupportedMediaType,
		"application/jsonx":                 http.StatusUnsupportedMediaType,
		"application/json-evil":             http.StatusUnsupportedMediaType,
		"":                                  http.StatusUnsupportedMediaType,
	} {
		rec := serve(e, http.MethodPost, "/scan", scanBody, func(r *http.Request) { r.Header.Set("Content-Type", ct) })
		assert.Equal(t, want, rec.Code, "Content-Type %q", ct)
	}
}

func Test_hostName(t *testing.T) {
	for in, want := range map[string]string{
		"localhost.:6664":       "localhost",
		"[::1]:6664":            "::1",
		"[::1]":                 "::1",
		"dalfox.internal:16664": "dalfox.internal",
		" dalfox.internal ":     "dalfox.internal",
		":6664":                 "",
	} {
		assert.Equal(t, want, hostName(in), in)
	}
	opts := &model.Options{AllowedHosts: []string{"dalfox.internal:16664"}}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "dalfox.internal:16664"
	assert.Empty(t, checkHost(req, opts), "--allowed-hosts entries may carry a port")
	req.Host = ":6664"
	assert.NotEmpty(t, checkHost(req, &model.Options{}), "an empty name never matches an empty --host")
}

func Test_setupEchoServer_ipv6Addr(t *testing.T) {
	for _, h := range []string{"::1", "[::1]"} {
		scans := []string{}
		e := setupEchoServer(&model.Options{ServerHost: h, ServerPort: 6664}, &scans)
		assert.Equal(t, "[::1]:6664", e.Server.Addr)
	}
}

func Test_prepareRESTScanOptions(t *testing.T) {
	rq := model.Options{OutputRequest: true, OutputResponse: true, FoundAction: "id"}
	prepareRESTScanOptions(&rq, &model.Options{})
	assert.False(t, rq.OutputRequest, "no API key: raw request must be stripped")
	assert.False(t, rq.OutputResponse, "no API key: raw response must be stripped")
	assert.Empty(t, rq.FoundAction)

	rq = model.Options{PoCType: "http-request", CookieFromRaw: "/nonexistent"}
	prepareRESTScanOptions(&rq, &model.Options{})
	assert.Equal(t, "plain", rq.PoCType, "no API key: http-request PoCs embed a request dump")
	assert.Empty(t, rq.CookieFromRaw, "server-side path; a missing file calls os.Exit")

	rq = model.Options{OutputRequest: true, OutputResponse: true, FoundAction: "id", PoCType: "http-request", CookieFromRaw: "/x"}
	prepareRESTScanOptions(&rq, &model.Options{APIKey: "k"})
	assert.Equal(t, "http-request", rq.PoCType)
	assert.Empty(t, rq.CookieFromRaw, "stripped regardless of auth")
	assert.True(t, rq.OutputRequest, "authenticated callers keep opt-in raw output")
	assert.True(t, rq.OutputResponse)
	assert.Empty(t, rq.FoundAction, "dangerous options are stripped regardless of auth")
}

func Test_serverExposureWarnings(t *testing.T) {
	assert.Empty(t, serverExposureWarnings(&model.Options{ServerHost: "127.0.0.1"}))
	assert.Empty(t, serverExposureWarnings(&model.Options{ServerHost: "::1"}))
	assert.Empty(t, serverExposureWarnings(&model.Options{ServerHost: "localhost"}))
	assert.Empty(t, serverExposureWarnings(&model.Options{ServerHost: "0.0.0.0", APIKey: "k"}))
	assert.Len(t, serverExposureWarnings(&model.Options{ServerHost: "0.0.0.0"}), 1)
	assert.Len(t, serverExposureWarnings(&model.Options{ServerHost: ""}), 1, "empty host binds every interface")
	assert.Len(t, serverExposureWarnings(&model.Options{ServerHost: "0.0.0.0", JSONP: true}), 2)
}

func Test_postScanHandler_stripsRawOutputWithoutAPIKey(t *testing.T) {
	got := stubScans(t)
	// Empty ServerType too: the strip must follow the key, not the type.
	for _, tc := range []struct {
		apiKey string
		keep   bool
	}{{"", false}, {"k", true}} {
		scans := []string{}
		options := model.Options{APIKey: tc.apiKey, Scan: map[string]model.Scan{}}
		e := setupEchoServer(&options, &scans)
		rec := serve(e, http.MethodPost, "/scan",
			`{"url":"http://127.0.0.1:1/","options":{"output-request":true,"output-response":true}}`,
			func(r *http.Request) { r.Header.Set(APIKeyHeader, tc.apiKey) })
		if !assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String()) {
			return
		}
		var rq model.Options
		select {
		case rq = <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("scan was never started")
		}
		assert.Equal(t, tc.keep, rq.OutputRequest, "api key %q", tc.apiKey)
		assert.Equal(t, tc.keep, rq.OutputResponse, "api key %q", tc.apiKey)
	}
}

func Test_redactEvidence(t *testing.T) {
	in := []model.PoC{
		{Payload: "<x>", Evidence: "3 line:  <p>SECRET=abc <x> tail-secret</p>\n    9 line:  y <x>\n    "},
		{Payload: "", Evidence: "1 line:  leak\n    "},
		{Payload: "<x>"},
	}
	out := redactEvidence(in)
	assert.Equal(t, "3 line:  <x>\n    9 line:  <x>\n    ", out[0].Evidence)
	assert.Equal(t, "1 line:  [redacted]\n    ", out[1].Evidence)
	assert.Empty(t, out[2].Evidence)
	assert.Equal(t, "[redacted]", redactEvidence([]model.PoC{{Payload: "p", Evidence: "free-form SECRET"}})[0].Evidence)
	assert.Contains(t, in[0].Evidence, "SECRET", "stored results must not be modified")
}

func Test_scanHandler_redactsEvidenceWithoutAPIKey(t *testing.T) {
	for _, tc := range []struct {
		apiKey string
		want   string
	}{{"", "1 line:  <x>\n    "}, {"k", "1 line:  SECRET <x>\n    "}} {
		scans := []string{"sid"}
		options := model.Options{APIKey: tc.apiKey, Scan: map[string]model.Scan{
			"sid": {URL: "http://internal/", Results: []model.PoC{{Payload: "<x>", Evidence: "1 line:  SECRET <x>\n    "}}},
		}}
		e := setupEchoServer(&options, &scans)
		rec := serve(e, http.MethodGet, "/scan/sid", "", func(r *http.Request) { r.Header.Set(APIKeyHeader, tc.apiKey) })
		if !assert.Equal(t, http.StatusOK, rec.Code) {
			continue
		}
		var res Res
		if assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res)) && assert.Len(t, res.Data, 1) {
			assert.Equal(t, tc.want, res.Data[0].Evidence, "api key %q", tc.apiKey)
		}
	}
}

func Test_responseHeaders_blockCrossOriginLoads(t *testing.T) {
	scans := []string{}
	e := setupEchoServer(&model.Options{Scan: map[string]model.Scan{}}, &scans)
	rec := serve(e, http.MethodGet, "/health", "", nil)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))
	// Rejected requests carry the headers too.
	rec = serve(e, http.MethodGet, "/health", "", func(r *http.Request) { r.Host = "evil.example" })
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Resource-Policy"))

	e = setupEchoServer(&model.Options{JSONP: true, Scan: map[string]model.Scan{}}, &scans)
	rec = serve(e, http.MethodGet, "/health?callback=cb", "", nil)
	assert.Equal(t, "cross-origin", rec.Header().Get("Cross-Origin-Resource-Policy"), "JSONP is loaded cross-origin by design")
}

// Test_originMatcher_neverLooserThanEchoCORS runs the real echo CORS
// middleware next to the guard: anything the guard lets through that CORS
// would refuse still runs server-side, so the guard may only be stricter.
func Test_originMatcher_neverLooserThanEchoCORS(t *testing.T) {
	patterns := [][]string{
		{"https://*.corp.example"},
		{"http://ui.local:300?"},
		{"https://exact.example/"},
		{"null"},
		{"https://a.*.corp.example"},
		{"http://localhost:*"},
	}
	origins := []string{
		"https://ui.corp.example", "https://a.b.corp.example", "https://corp.example",
		"https://evilcorp.example", "http://ui.local:3001", "http://ui.local:30011",
		"https://exact.example", "https://exact.example/", "null",
		"https://x.y.corp.example", "https://a.x.corp.example", "http://localhost:3000",
		"https://" + strings.Repeat("a", 260) + ".corp.example",
	}
	for _, allowed := range patterns {
		e := echo.New()
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: allowed}))
		e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		m := newOriginMatcher(allowed)
		for _, o := range origins {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", o)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			cors := rec.Header().Get("Access-Control-Allow-Origin") != ""
			if m.allows(o) {
				assert.True(t, cors, "guard allows %q for %v but echo CORS does not", o, allowed)
			}
		}
	}
	// The everyday shapes must agree in the other direction too.
	m := newOriginMatcher([]string{"https://*.corp.example", "http://localhost:*"})
	assert.True(t, m.allows("https://ui.corp.example"))
	assert.True(t, m.allows("http://localhost:3000"))
	assert.True(t, newOriginMatcher([]string{"null"}).allows("null"), "exact entries skip the :// pre-check, as in echo")
}

func Test_sameOrigin_defaultPorts(t *testing.T) {
	assert.True(t, sameOrigin("https://dalfox.internal", "dalfox.internal:443"))
	assert.True(t, sameOrigin("http://dalfox.internal", "dalfox.internal:80"))
	assert.True(t, sameOrigin("http://dalfox.internal:80", "dalfox.internal"))
	assert.True(t, sameOrigin("http://[::1]:6664", "[::1]:6664"))
	assert.False(t, sameOrigin("https://dalfox.internal", "dalfox.internal:80"))
	assert.False(t, sameOrigin("http://dalfox.internal", "dalfox.internal:6664"))
	assert.False(t, sameOrigin("http://127.0.0.1:6664", "localhost:6664"))
	assert.False(t, sameOrigin("null", "localhost"))
}

func Test_sanitizeAPIScanOptions_crashValues(t *testing.T) {
	o := model.Options{Concurrence: -1, Timeout: -1, Delay: -5, Trigger: "://bad"}
	sanitizeAPIScanOptions(&o)
	assert.Equal(t, 0, o.Concurrence, "make(chan, -1) panics")
	assert.Equal(t, 0, o.Timeout)
	assert.Equal(t, 0, o.Delay)
	assert.Empty(t, o.Trigger, "an unparsable trigger yields a nil request")

	o = model.Options{Concurrence: 1 << 30, Trigger: "http://127.0.0.1/?s=SEQNC"}
	sanitizeAPIScanOptions(&o)
	assert.Equal(t, maxAPIWorkers, o.Concurrence)
	assert.Equal(t, "http://127.0.0.1/?s=SEQNC", o.Trigger)
	for _, bad := range []string{"javascript:alert(1)", "file:///etc/passwd", "/relative", "http://"} {
		o = model.Options{Trigger: bad}
		sanitizeAPIScanOptions(&o)
		assert.Empty(t, o.Trigger, bad)
	}
}

func Test_postScanHandler_passesSanitizedOptions(t *testing.T) {
	got := stubScans(t)
	scans := []string{}
	options := model.Options{Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)
	rec := serve(e, http.MethodPost, "/scan", `{"url":"http://127.0.0.1:1/","options":{
		"found-action":"id","cookie-from-raw":"/x","custom-payload-file":"/etc/hostname",
		"worker":-1,"trigger":"://bad","poc-type":"http-request","output-response":true}}`, nil)
	if !assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String()) {
		return
	}
	select {
	case rq := <-got:
		assert.Empty(t, rq.FoundAction)
		assert.Empty(t, rq.CookieFromRaw)
		assert.Empty(t, rq.CustomPayloadFile)
		assert.Equal(t, 0, rq.Concurrence)
		assert.Empty(t, rq.Trigger)
		assert.Equal(t, "plain", rq.PoCType)
		assert.False(t, rq.OutputResponse)
	case <-time.After(5 * time.Second):
		t.Fatal("scan was never started")
	}
}

func Test_swaggerSpecFollowsTheServerAddress(t *testing.T) {
	scans := []string{}
	e := setupEchoServer(&model.Options{Scan: map[string]model.Scan{}}, &scans)
	rec := serve(e, http.MethodGet, "/swagger/doc.json", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	var spec map[string]interface{}
	if assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &spec)) {
		host, _ := spec["host"].(string)
		assert.Empty(t, host, "a fixed host makes Swagger UI cross-origin when opened on another address")
	}
}
