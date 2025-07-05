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

	// CORS Middleware
	if options.ServerType == "rest" && len(options.AllowedOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: options.AllowedOrigins,
			AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
		}))
	}

	// API Key Authentication Middleware
	if options.ServerType == "rest" && options.APIKey != "" {
		e.Use(apiKeyAuth(options.APIKey, options)) // Pass options for JSONP check
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
	e.GET("/health", func(c echo.Context) error {
		return healthHandler(c, options)
	})
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/scans", func(c echo.Context) error {
		return scansHandler(c, scans, options)
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
func apiKeyAuth(validAPIKey string, options *model.Options) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get(APIKeyHeader)
			if apiKey == "" || apiKey != validAPIKey {
				res := Res{Code: http.StatusUnauthorized, Msg: "Unauthorized: Invalid or missing API Key"}
				if options.ServerType == "rest" && options.JSONP {
					callbackParam := c.QueryParam("callback")
					if callbackParam != "" {
						return c.JSONP(http.StatusUnauthorized, callbackParam, res)
					}
				}
				return c.JSON(http.StatusUnauthorized, res)
			}
			return next(c)
		}
	}
}

func healthHandler(c echo.Context, options *model.Options) error {
	r := &Res{
		Code: 200,
		Msg:  "ok",
	}
	if options.ServerType == "rest" && options.JSONP {
		callbackParam := c.QueryParam("callback")
		if callbackParam != "" {
			return c.JSONP(http.StatusOK, callbackParam, r)
		}
	}
	return c.JSON(http.StatusOK, r)
}

func scansHandler(c echo.Context, scans *[]string, options *model.Options) error {
	r := &Scans{
		Code:  200,
		Scans: *scans,
	}
	// It seems this handler intends to return 404 if scans is empty,
	// but the plan is to use JSONP for successful responses.
	// For now, let's assume 200 is the intended success status for JSONP.
	// If scans is empty and it's meant to be a 404, JSONP might not be conventional.
	// The original code returns http.StatusNotFound, let's keep that for non-JSONP.
	status := http.StatusOK // Assuming 200 for successful JSONP response
	if len(*scans) == 0 { // A more explicit check for emptiness
		status = http.StatusNotFound
	}

	if options.ServerType == "rest" && options.JSONP {
		callbackParam := c.QueryParam("callback")
		if callbackParam != "" {
			// If it was truly a "not found" scenario even for JSONP, this might need adjustment.
			// For now, sending the Scans struct (even if empty) with the callback.
			return c.JSONP(status, callbackParam, r)
		}
	}
	// Original behavior if not JSONP or no callback
	if status == http.StatusNotFound {
		return c.JSON(http.StatusNotFound, Res{Code: http.StatusNotFound, Msg: "No scans found"})
	}
	return c.JSON(status, r)
}

func scanHandler(c echo.Context, scans *[]string, options *model.Options) error {
	sid := c.Param("sid")
	scanData, inOptionsScan := options.Scan[sid]
	scanResult := GetScan(sid, *options)

	res := &Res{}
	status := http.StatusOK

	if !inOptionsScan && !contains(*scans, sid) {
		status = http.StatusNotFound
		res.Code = http.StatusNotFound
		res.Msg = "Scan ID not found"
	} else {
		res.Code = http.StatusOK
		if !inOptionsScan || len(scanResult.URL) == 0 {
			if contains(*scans, sid) {
				res.Msg = "scanning"
			} else {
				status = http.StatusNotFound
				res.Code = http.StatusNotFound
				res.Msg = "Scan ID not found or not initialized"
			}
		} else {
			res.Msg = "finish"
			res.Data = scanData.Results
		}
	}

	if options.ServerType == "rest" && options.JSONP {
		callbackParam := c.QueryParam("callback")
		if callbackParam != "" {
			return c.JSONP(status, callbackParam, res)
		}
	}
	return c.JSON(status, res)
}

func postScanHandler(c echo.Context, scans *[]string, options *model.Options) error {
	rq := new(Req)
	if err := c.Bind(rq); err != nil {
		res := &Res{
			Code: http.StatusInternalServerError,
			Msg:  "Parameter Bind error",
		}
		if options.ServerType == "rest" && options.JSONP {
			callbackParam := c.QueryParam("callback")
			if callbackParam != "" {
				return c.JSONP(http.StatusInternalServerError, callbackParam, res)
			}
		}
		return c.JSON(http.StatusInternalServerError, res)
	}
	sid := utils.GenerateRandomToken(rq.URL)
	res := &Res{
		Code: http.StatusOK,
		Msg:  sid,
	}
	*scans = append(*scans, sid)
	if options.Scan == nil {
		options.Scan = make(map[string]model.Scan)
	}
	go ScanFromAPI(rq.URL, rq.Options, *options, sid)

	if options.ServerType == "rest" && options.JSONP {
		callbackParam := c.QueryParam("callback")
		if callbackParam != "" {
			return c.JSONP(http.StatusOK, callbackParam, res)
		}
	}
	return c.JSON(http.StatusOK, res)
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
