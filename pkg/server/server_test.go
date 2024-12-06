package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
