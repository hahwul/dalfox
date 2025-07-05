package server

import (
	"net/http"
	"strconv"
	"time"

	printing "github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/utils"
	"github.com/hahwul/dalfox/v2/pkg/model"
	_ "github.com/hahwul/dalfox/v2/pkg/server/docs"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
	"github.com/tylerb/graceful"
)

const APIKeyHeader = "X-API-KEY"

// @title Dalfox API
// @version 1.0
// @description This is a dalfox api swagger
// @termsOfService http://swagger.io/terms/

// @license.name MIT
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:6664
// @BasePath /

// RunAPIServer is Running Echo server with swag
func RunAPIServer(options model.Options) {
	var scans []string
	// Initialize options.Scan if it's nil
	if options.Scan == nil {
		options.Scan = make(map[string]model.Scan)
	}
	e := setupEchoServer(&options, &scans)                      // Pass address of options
	printing.DalLog("SYSTEM", "Listen "+e.Server.Addr, options) // Pass options by value
	graceful.ListenAndServe(e.Server, 5*time.Second)
}

func setupEchoServer(options *model.Options, scans *[]string) *echo.Echo { // options is now a pointer
	e := echo.New()
	options.IsAPI = true
	e.Server.Addr = options.ServerHost + ":" + strconv.Itoa(options.ServerPort)

	// API Key Authentication Middleware
	if options.ServerType == "rest" && options.APIKey != "" {
		e.Use(apiKeyAuth(options.APIKey))
	}

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "",
		ContentTypeNosniff: "",
		XFrameOptions:      "",
		HSTSMaxAge:         3600,
	}))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}","host":"${host}",` +
			`"method":"${method}","uri":"${uri}","status":${status},"error":"${error}","latency":${latency},` +
			`"latency_human":"${latency_human}","bytes_in":${bytes_in},` +
			`"bytes_out":${bytes_out}}` + "\n",
	}))
	e.GET("/health", healthHandler)
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/scans", func(c echo.Context) error {
		return scansHandler(c, scans)
	})
	e.GET("/scan/:sid", func(c echo.Context) error {
		return scanHandler(c, scans, options) // Pass pointer directly
	})
	e.POST("/scan", func(c echo.Context) error {
		return postScanHandler(c, scans, options) // Pass pointer directly
	})
	e.DELETE("/scans/all", func(c echo.Context) error {
		return deleteScansHandler(c, scans, options) // options is already a pointer
	})
	e.DELETE("/scan/:sid", func(c echo.Context) error {
		return deleteScanHandler(c, scans, options) // options is already a pointer
	})
	return e
}

// apiKeyAuth is a middleware function for API key authentication
func apiKeyAuth(validAPIKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get API key from request header

			apiKey := c.Request().Header.Get(APIKeyHeader)

			// If API key is empty or invalid, return 401 Unauthorized
			if apiKey == "" || apiKey != validAPIKey {
				return c.JSON(http.StatusUnauthorized, Res{Code: http.StatusUnauthorized, Msg: "Unauthorized: Invalid or missing API Key"})
			}

			// If API key is valid, proceed to the next handler
			return next(c)
		}
	}
}

func healthHandler(c echo.Context) error {
	r := &Res{
		Code: 200,
		Msg:  "ok",
	}
	return c.JSON(http.StatusOK, r)
}

func scansHandler(c echo.Context, scans *[]string) error {
	r := &Scans{
		Code:  200,
		Scans: *scans,
	}
	return c.JSON(http.StatusNotFound, r)
}

func scanHandler(c echo.Context, scans *[]string, options *model.Options) error { // options is now *model.Options
	sid := c.Param("sid")
	// Check if sid exists in options.Scan (source of truth) or in the scans slice for active scanning processes
	scanData, inOptionsScan := options.Scan[sid] // This will now use the pointer's Scan field
	scanResult := GetScan(sid, *options)         // Dereference options for GetScan

	if !inOptionsScan && !contains(*scans, sid) { // If not in options.Scan and not in scans slice
		return c.JSON(http.StatusNotFound, Res{Code: 404, Msg: "Scan ID not found"})
	}

	r := &Res{Code: 200}
	if !inOptionsScan || len(scanResult.URL) == 0 { // Use scanResult.URL
		// Check if it was at least in the scans slice, meaning it's a known scan process
		if contains(*scans, sid) {
			r.Msg = "scanning"
		} else {
			// This case should ideally not be reached if the first check is comprehensive
			// but as a fallback if it's not in options.Scan and somehow missed in the initial scans check.
			return c.JSON(http.StatusNotFound, Res{Code: 404, Msg: "Scan ID not found or not initialized"})
		}
	} else {
		r.Msg = "finish"
		r.Data = scanData.Results // Use scanData from options.Scan if available and finished
	}
	return c.JSON(http.StatusOK, r)
}

func postScanHandler(c echo.Context, scans *[]string, options *model.Options) error { // options is now *model.Options
	rq := new(Req)
	if err := c.Bind(rq); err != nil {
		r := &Res{
			Code: 500,
			Msg:  "Parameter Bind error",
		}
		return c.JSON(http.StatusInternalServerError, r)
	}
	sid := utils.GenerateRandomToken(rq.URL)
	r := &Res{
		Code: 200,
		Msg:  sid,
	}
	*scans = append(*scans, sid)
	// Ensure options.Scan is initialized before use in ScanFromAPI
	if options.Scan == nil { // options is a pointer, so options.Scan is fine
		options.Scan = make(map[string]model.Scan)
	}
	go ScanFromAPI(rq.URL, rq.Options, *options, sid) // Dereference options
	return c.JSON(http.StatusOK, r)
}

// @Summary Delete all scans
// @Description Deletes all recorded scan data
// @Tags scans
// @Accept json
// @Produce json
// @Success 200 {object} Res "All scans deleted"
// @Router /scans/all [delete]
// deleteScansHandler clears all scan data
func deleteScansHandler(c echo.Context, scans *[]string, options *model.Options) error {
	*scans = []string{}
	if options.Scan != nil {
		options.Scan = make(map[string]model.Scan)
	}
	return c.JSON(http.StatusOK, Res{Code: 200, Msg: "All scans deleted"})
}

// @Summary Delete a specific scan
// @Description Deletes a scan by its ID
// @Tags scans
// @Accept json
// @Produce json
// @Param sid path string true "Scan ID"
// @Success 200 {object} Res "Scan deleted successfully"
// @Failure 404 {object} Res "Scan ID not found"
// @Router /scan/{sid} [delete]
// deleteScanHandler deletes a specific scan by its ID
func deleteScanHandler(c echo.Context, scans *[]string, options *model.Options) error {
	sid := c.Param("sid")

	// Check if sid exists in options.Scan (source of truth) or in the scans slice
	_, inOptionsScan := options.Scan[sid]
	inScansSlice := contains(*scans, sid)

	if !inOptionsScan && !inScansSlice {
		return c.JSON(http.StatusNotFound, Res{Code: 404, Msg: "Scan ID not found"})
	}

	// Remove sid from scans slice
	if inScansSlice {
		newScans := []string{}
		for _, s := range *scans {
			if s != sid {
				newScans = append(newScans, s)
			}
		}
		*scans = newScans
	}

	// Delete from options.Scan map
	if inOptionsScan {
		delete(options.Scan, sid)
	}

	return c.JSON(http.StatusOK, Res{Code: 200, Msg: "Scan deleted successfully"})
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
