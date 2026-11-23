package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/labstack/echo/v4"
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
	assert.Equal(t, http.StatusNoContent, preflight("127.0.0.1:6664"))
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
		assert.Equal(t, http.StatusUnauthorized, serve(e, http.MethodGet, "/scans", "", nil).Code, "ServerType %q", st)
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
