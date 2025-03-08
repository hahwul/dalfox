package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	_ "github.com/hahwul/dalfox/v2/pkg/server/docs"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func Test_contains(t *testing.T) {
	type args struct {
		slice []string
		item  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Item exists", args: args{slice: []string{"a", "b", "c"}, item: "b"}, want: true},
		{name: "Item does not exist", args: args{slice: []string{"a", "b", "c"}, item: "d"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.args.slice, tt.args.item); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_scanHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/scan/test-scan", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	scans := []string{"test-scan"}
	options := model.Options{
		Scan: map[string]model.Scan{
			"test-scan": {URL: "http://example.com", Results: []model.PoC{{Type: "finish"}}},
		},
	}

	if assert.NoError(t, scanHandler(c, &scans, options)) {
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "Not found")
	}
}

func Test_scansHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	scans := []string{"test-scan"}

	if assert.NoError(t, scansHandler(c, &scans)) {
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "test-scan")
	}
}

func Test_healthHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if assert.NoError(t, healthHandler(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	}
}

func Test_postScanHandler(t *testing.T) {
	e := echo.New()
	rq := Req{
		URL: "http://example.com",
		Options: model.Options{
			Method: "GET",
		},
	}
	body, _ := json.Marshal(rq)
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	scans := []string{}
	options := model.Options{
		Scan: map[string]model.Scan{},
	}

	if assert.NoError(t, postScanHandler(c, &scans, options)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "code")
		assert.Contains(t, rec.Body.String(), "msg")
		assert.Contains(t, rec.Body.String(), "data")
	}
}

func Test_GetScan(t *testing.T) {
	options := model.Options{
		Scan: map[string]model.Scan{
			"test-scan": {URL: "http://example.com", Results: []model.PoC{{Type: "finish"}}},
		},
	}
	scan := GetScan("test-scan", options)
	assert.Equal(t, "http://example.com", scan.URL)
	assert.Equal(t, "finish", scan.Results[0].Type)
}

func Test_GetScans(t *testing.T) {
	options := model.Options{
		Scan: map[string]model.Scan{
			"test-scan1": {URL: "http://example1.com"},
			"test-scan2": {URL: "http://example2.com"},
		},
	}
	scans := GetScans(options)
	assert.Contains(t, scans, "test-scan1")
	assert.Contains(t, scans, "test-scan2")
}

func Test_ScanFromAPI(t *testing.T) {
	options := model.Options{
		Debug: true,
		Scan:  map[string]model.Scan{},
	}
	rqOptions := model.Options{
		Method: "GET",
	}
	sid := "test-scan-id"

	t.Run("Successful Scan", func(t *testing.T) {
		ScanFromAPI("http://example.com", rqOptions, options, sid)
		// Add assertions to verify the scan was successful
	})

	t.Run("Scan with Error", func(t *testing.T) {
		ScanFromAPI("http://invalid-url", rqOptions, options, sid)
		// Add assertions to verify error handling
	})
}

func Test_setupEchoServer(t *testing.T) {
	options := model.Options{
		ServerHost: "localhost",
		ServerPort: 6664,
	}
	scans := []string{}
	e := setupEchoServer(options, &scans)

	assert.NotNil(t, e)
	assert.Equal(t, "localhost:6664", e.Server.Addr)
}

func Test_RunAPIServer(t *testing.T) {
	options := model.Options{
		ServerHost: "localhost",
		ServerPort: 6664,
	}
	go RunAPIServer(options)
	time.Sleep(1 * time.Second)

	resp, err := http.Get("http://localhost:6664/health")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
