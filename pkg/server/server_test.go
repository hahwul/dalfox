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

func TestScanHandler(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/scan/test-scan-notfound", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues("test-scan-notfound")

		scans := []string{} // SID not in scans
		options := model.Options{
			Scan: make(map[string]model.Scan), // SID not in options.Scan
		}

		if assert.NoError(t, scanHandler(c, &scans, &options)) {
			assert.Equal(t, http.StatusNotFound, rec.Code)
			expectedJSON := `{"code":404, "msg":"Scan ID not found", "data":null}`
			assert.JSONEq(t, expectedJSON, rec.Body.String())
		}
	})

	t.Run("ScanningState", func(t *testing.T) {
		e := echo.New()
		sid := "scanning_id"
		req := httptest.NewRequest(http.MethodGet, "/scan/"+sid, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues(sid)

		scans := []string{sid}
		options := model.Options{
			Scan: make(map[string]model.Scan),
		}
		// SID is in scans slice, but not yet fully in options.Scan map or its URL is empty
		// The GetScan function will return an empty model.Scan if not found in options.Scan
		// For "scanning" state, the primary check is often that it's in the `scans` slice
		// and GetScan returns an empty URL.
		// Let's ensure options.Scan does not have 'sid' or has it with an empty URL.
		// Current scanHandler logic: `if !inOptionsScan || len(scanResult.URL) == 0`
		// and `if contains(*scans, sid)` -> r.Msg = "scanning"

		if assert.NoError(t, scanHandler(c, &scans, &options)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			expectedJSON := `{"code":200, "msg":"scanning", "data":null}`
			assert.JSONEq(t, expectedJSON, rec.Body.String())
		}
	})

	t.Run("FinishState", func(t *testing.T) {
		e := echo.New()
		sid := "finished_id"
		req := httptest.NewRequest(http.MethodGet, "/scan/"+sid, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues(sid)

		dummyResults := []model.PoC{{Type: "test-poc", InjectType: "G", PoCType: "R", Method: "GET", Data: "dummy", Param: "p", Payload: "alert(1)", Evidence: "alert(1)", CWE: "CWE-79", Severity: "High"}}

		scans := []string{sid} // It might or might not be in scans slice if finished, but must be in options.Scan
		options := model.Options{
			Scan: make(map[string]model.Scan),
		}
		options.Scan[sid] = model.Scan{URL: "http://test.com/vuln", ScanID: sid, Results: dummyResults}

		if assert.NoError(t, scanHandler(c, &scans, &options)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			// Note: The model.PoC struct has json tags like "inject_type", "poc_type".
			// Ensure these match the expected JSON.
			expectedJSON := `{"code":200, "msg":"finish", "data":[{"type":"test-poc","inject_type":"G","poc_type":"R","method":"GET","data":"dummy","param":"p","payload":"alert(1)","evidence":"alert(1)","cwe":"CWE-79","severity":"High"}]}`
			assert.JSONEq(t, expectedJSON, rec.Body.String())
		}
	})
}

func Test_scansHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	scans := []string{"test-scan"}
	options := model.Options{}

	if assert.NoError(t, scansHandler(c, &scans, &options)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "test-scan")
	}
}

func Test_healthHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	options := model.Options{}

	if assert.NoError(t, healthHandler(c, &options)) {
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

	if assert.NoError(t, postScanHandler(c, &scans, &options)) { // Pass address of options
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
	e := setupEchoServer(&options, &scans) // Pass address of options

	assert.NotNil(t, e)
	assert.Equal(t, "localhost:6664", e.Server.Addr)
}

func Test_RunAPIServer(t *testing.T) {
	options := model.Options{
		ServerHost: "localhost",
		ServerPort: 6664,
		Scan:       make(map[string]model.Scan), // Ensure Scan is initialized
	}
	go RunAPIServer(options)
	time.Sleep(1 * time.Second)

	resp, err := http.Get("http://localhost:6664/health")
	assert.NoError(t, err)
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
}

func Test_apiKeyAuth(t *testing.T) {
	e := echo.New()
	validKey := "test-api-key"
	options := model.Options{}
	mw := apiKeyAuth(validKey, &options)

	// Dummy handler to check if middleware passes
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Case 1: Valid API Key
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(APIKeyHeader, validKey)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := mw(handler)(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())

	// Case 2: Missing API Key
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	err = mw(handler)(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Unauthorized")

	// Case 3: Invalid API Key
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(APIKeyHeader, "wrong-key")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	err = mw(handler)(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Unauthorized")
}

func TestDeleteScansHandler(t *testing.T) {
	options := model.Options{Scan: make(map[string]model.Scan)}
	options.Scan["id1"] = model.Scan{URL: "http://test1", ScanID: "id1"}
	options.Scan["id2"] = model.Scan{URL: "http://test2", ScanID: "id2"}
	scans := []string{"id1", "id2"}

	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/scans/all", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := deleteScansHandler(c, &scans, &options)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, rec.Code)

	expectedJSON := `{"code":200,"msg":"All scans deleted", "data":null}`
	assert.JSONEq(t, expectedJSON, rec.Body.String())

	assert.Len(t, scans, 0)
	assert.Len(t, options.Scan, 0)
}

func TestDeleteScanHandler(t *testing.T) {
	t.Run("Delete an existing scan", func(t *testing.T) {
		options := model.Options{Scan: make(map[string]model.Scan)}
		options.Scan["id1"] = model.Scan{URL: "http://test1", ScanID: "id1"}
		options.Scan["id2"] = model.Scan{URL: "http://test2", ScanID: "id2"}
		scans := []string{"id1", "id2"}

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/scan/id1", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues("id1")

		err := deleteScanHandler(c, &scans, &options)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code)
		expectedJSON := `{"code":200,"msg":"Scan deleted successfully", "data":null}`
		assert.JSONEq(t, expectedJSON, rec.Body.String())

		assert.Equal(t, []string{"id2"}, scans)
		_, exists := options.Scan["id1"]
		assert.False(t, exists)
		_, exists = options.Scan["id2"]
		assert.True(t, exists)
		assert.Len(t, options.Scan, 1)
	})

	t.Run("Delete a non-existent scan", func(t *testing.T) {
		options := model.Options{Scan: make(map[string]model.Scan)}
		options.Scan["id1"] = model.Scan{URL: "http://test1", ScanID: "id1"}
		scans := []string{"id1"}

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/scan/nonexistent", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues("nonexistent")

		err := deleteScanHandler(c, &scans, &options)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		expectedJSON := `{"code":404,"msg":"Scan ID not found", "data":null}`
		assert.JSONEq(t, expectedJSON, rec.Body.String())

		assert.Equal(t, []string{"id1"}, scans)
		_, exists := options.Scan["id1"]
		assert.True(t, exists)
		assert.Len(t, options.Scan, 1)
	})

	t.Run("Delete an existing scan in options.Scan but not in scans slice", func(t *testing.T) {
		options := model.Options{Scan: make(map[string]model.Scan)}
		scanIDInMapOnly := "id_only_in_map"
		options.Scan[scanIDInMapOnly] = model.Scan{URL: "http://test.com", ScanID: scanIDInMapOnly}

		otherID := "other_id"
		scans := []string{otherID} // scanIDInMapOnly is NOT in this slice

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/scan/"+scanIDInMapOnly, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("sid")
		c.SetParamValues(scanIDInMapOnly)

		err := deleteScanHandler(c, &scans, &options)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code)
		expectedJSON := `{"code":200,"msg":"Scan deleted successfully", "data":null}`
		assert.JSONEq(t, expectedJSON, rec.Body.String())

		// Assert that "id_only_in_map" is no longer in options.Scan
		_, existsInMap := options.Scan[scanIDInMapOnly]
		assert.False(t, existsInMap)

		// Assert that the scans slice remains []string{"other_id"}
		assert.Equal(t, []string{otherID}, scans)
		assert.Len(t, options.Scan, 0) // Since only scanIDInMapOnly was in options.Scan
	})
}
