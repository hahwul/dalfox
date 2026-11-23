package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
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
		got := checkCrossSite(req, opts)
		assert.Equal(t, tc.ok, got == "", "%s: %q", tc.name, got)
	}

	// --jsonp exists to be read cross-origin, so it opts out.
	req := httptest.NewRequest(http.MethodGet, "/scan/x", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	assert.Empty(t, checkCrossSite(req, &model.Options{JSONP: true}))
}

func Test_requestSourceGuard_onServer(t *testing.T) {
	scans := []string{}
	options := model.Options{ServerType: "rest", ServerHost: "127.0.0.1", Scan: map[string]model.Scan{}}
	e := setupEchoServer(&options, &scans)

	send := func(mutate func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"url":"http://127.0.0.1:1/"}`))
		req.Host = "127.0.0.1:6664"
		req.Header.Set("Content-Type", "application/json")
		mutate(req)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	rec := send(func(*http.Request) {})
	assert.Equal(t, http.StatusOK, rec.Code, "curl-style client must keep working")

	rec = send(func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = send(func(r *http.Request) { r.Host = "rebind.evil.example:6664" })
	assert.Equal(t, http.StatusForbidden, rec.Code, "DNS-rebound Host must be rejected")

	rec = send(func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)

	// /health is browser-probeable too; the guard covers every route.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func Test_prepareRESTScanOptions(t *testing.T) {
	rq := model.Options{OutputRequest: true, OutputResponse: true, FoundAction: "id"}
	prepareRESTScanOptions(&rq, &model.Options{})
	assert.False(t, rq.OutputRequest, "no API key: raw request must be stripped")
	assert.False(t, rq.OutputResponse, "no API key: raw response must be stripped")
	assert.Empty(t, rq.FoundAction)

	rq = model.Options{OutputRequest: true, OutputResponse: true, FoundAction: "id"}
	prepareRESTScanOptions(&rq, &model.Options{APIKey: "k"})
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
	got := make(chan model.Options, 1)
	orig := startAPIScan
	startAPIScan = func(_ string, rq model.Options, _ model.Options, _ string) { got <- rq }
	defer func() { startAPIScan = orig }()

	for _, tc := range []struct {
		apiKey string
		keep   bool
	}{{"", false}, {"k", true}} {
		scans := []string{}
		options := model.Options{ServerType: "rest", APIKey: tc.apiKey, Scan: map[string]model.Scan{}}
		e := setupEchoServer(&options, &scans)
		req := httptest.NewRequest(http.MethodPost, "/scan",
			strings.NewReader(`{"url":"http://127.0.0.1:1/","options":{"output-request":true,"output-response":true}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Host = "127.0.0.1:6664"
		req.Header.Set(APIKeyHeader, tc.apiKey)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
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
