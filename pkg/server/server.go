package server

import (
	"crypto/subtle"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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

// respondJSONorJSONP is a helper to send JSON or JSONP responses based on options and callback param
func respondJSONorJSONP(c echo.Context, status int, resp interface{}, options *model.Options) error {
	if options.ServerType == "rest" && options.JSONP {
		callbackParam := c.QueryParam("callback")
		if callbackParam != "" {
			return c.JSONP(status, callbackParam, resp)
		}
	}
	return c.JSON(status, resp)
}

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
	printServerWarnings(&options)
	e := setupEchoServer(&options, &scans)                      // Pass address of options
	printing.DalLog("SYSTEM", "Listen "+e.Server.Addr, options) // Pass options by value
	if err := graceful.ListenAndServe(e.Server, 5*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "[ERROR] REST API server: "+err.Error())
	}
}

func setupEchoServer(options *model.Options, scans *[]string) *echo.Echo { // options is now a pointer
	e := echo.New()
	options.IsAPI = true
	// This is the REST server whatever --type said: every gate below used to
	// key on ServerType == "rest", so `--type REST` or a library caller with
	// an empty ServerType silently ran without the API key check.
	options.ServerType = "rest"
	host := strings.TrimSuffix(strings.TrimPrefix(options.ServerHost, "["), "]")
	e.Server.Addr = net.JoinHostPort(host, strconv.Itoa(options.ServerPort))
	for i, o := range options.AllowedOrigins {
		options.AllowedOrigins[i] = strings.TrimSpace(o)
	}

	// Logging and security headers first, so rejected requests are logged too.
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

	// Without an API key, the request source is the only thing keeping a web
	// page out (GHSA-c98c-mph6-6hm9). With one, a page cannot attach the
	// X-API-KEY header without CORS approval, so the guard would add nothing
	// but breakage for clients that address the server by a service name.
	// It runs before CORS so preflights get the Host check as well.
	if !authEnabled(options) {
		e.Use(requestSourceGuard(options))
	}

	// CORS Middleware (before the API key so preflights, which carry no key,
	// are answered)
	if len(options.AllowedOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: options.AllowedOrigins,
			AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
		}))
	}

	// API Key Authentication Middleware
	if authEnabled(options) {
		e.Use(apiKeyAuth(options.APIKey, options)) // Pass options for JSONP check
	}
	e.GET("/health", func(c echo.Context) error {
		return healthHandler(c, options)
	})
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/scans", func(c echo.Context) error {
		return scansHandler(c, scans, options)
	})
	e.GET("/scan/:sid", func(c echo.Context) error {
		return scanHandler(c, scans, options)
	})
	e.POST("/scan", func(c echo.Context) error {
		return postScanHandler(c, scans, options)
	})
	e.DELETE("/scans/all", func(c echo.Context) error {
		return deleteScansHandler(c, scans, options)
	})
	e.DELETE("/scan/:sid", func(c echo.Context) error {
		return deleteScanHandler(c, scans, options)
	})
	return e
}

// apiKeyAuth is a middleware function for API key authentication
func apiKeyAuth(validAPIKey string, options *model.Options) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get(APIKeyHeader)
			if apiKey == "" || subtle.ConstantTimeCompare([]byte(apiKey), []byte(validAPIKey)) != 1 {
				res := Res{Code: http.StatusUnauthorized, Msg: "Unauthorized: Invalid or missing API Key"}
				return respondJSONorJSONP(c, http.StatusUnauthorized, res, options)
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
	return respondJSONorJSONP(c, http.StatusOK, r, options)
}

func scansHandler(c echo.Context, scans *[]string, options *model.Options) error {
	r := &Scans{
		Code:  200,
		Scans: *scans,
	}
	status := http.StatusOK
	if len(*scans) == 0 {
		status = http.StatusNotFound
		// For empty scans, respond with a not found message
		return respondJSONorJSONP(c, status, Res{Code: http.StatusNotFound, Msg: "No scans found"}, options)
	}
	return respondJSONorJSONP(c, status, r, options)
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

	return respondJSONorJSONP(c, status, res, options)
}

// sanitizeAPIScanOptions strips fields that would let an API caller drive
// host-side filesystem or shell execution. These options are only safe for
// local CLI users; in REST/MCP mode the caller is the request body, so we
// refuse to honor them regardless of authentication state.
//
// See GHSA-v25v-m36w-jp4h, GHSA-8hf9-3q64-q2qf, GHSA-35wr-x7v6-9fv2.
func sanitizeAPIScanOptions(o *model.Options) {
	o.FoundAction = ""
	o.FoundActionShell = ""
	o.OutputFile = ""
	o.OutputAll = false
	o.CustomPayloadFile = ""
	o.CustomBlindXSSPayloadFile = ""
	o.HarFilePath = ""
	// MiningWordlist (mining-dict-word) is also a server-side file path read
	// by voltFile.ReadLinesOrLiteral; lines become probed parameter names and
	// are exfiltrated through scan traffic — same class as CustomPayloadFile.
	o.MiningWordlist = ""
	// CookieFromRaw is a server-side path too: it is opened per request, its
	// Cookie header is sent to the scan target, and a missing or unparsable
	// file calls os.Exit(1), so one request could stop the server.
	o.CookieFromRaw = ""
}

// stripRawHTTPOutput drops raw request/response capture from findings. With
// no API key, whoever can reach the port would otherwise read the full body
// of any internal page dalfox can reach (GHSA-c98c-mph6-6hm9).
func stripRawHTTPOutput(o *model.Options) {
	o.OutputRequest = false
	o.OutputResponse = false
	// "http-request" PoCs embed a full request dump in the finding's data.
	if strings.EqualFold(strings.TrimSpace(o.PoCType), "http-request") {
		o.PoCType = "plain"
	}
}

// authEnabled reports whether the REST server checks X-API-KEY.
func authEnabled(server *model.Options) bool {
	return server.APIKey != ""
}

// prepareRESTScanOptions applies every scrub a REST scan request goes through.
func prepareRESTScanOptions(rq *model.Options, server *model.Options) {
	sanitizeAPIScanOptions(rq)
	if !authEnabled(server) {
		stripRawHTTPOutput(rq)
	}
}

// startAPIScan is swapped in tests to observe the options a scan starts with.
var startAPIScan = ScanFromAPI

func postScanHandler(c echo.Context, scans *[]string, options *model.Options) error {
	// JSON only. Req has no `form` tags, so a form-encoded body never filled
	// in the URL anyway; this turns that silent empty-URL scan into an error
	// and keeps preflight-free cross-site bodies out by construction.
	if mt, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType)); err != nil || mt != echo.MIMEApplicationJSON {
		res := &Res{
			Code: http.StatusUnsupportedMediaType,
			Msg:  "Content-Type must be application/json",
		}
		return respondJSONorJSONP(c, http.StatusUnsupportedMediaType, res, options)
	}
	rq := new(Req)
	if err := c.Bind(rq); err != nil {
		res := &Res{
			Code: http.StatusInternalServerError,
			Msg:  "Parameter Bind error",
		}
		return respondJSONorJSONP(c, http.StatusInternalServerError, res, options)
	}
	prepareRESTScanOptions(&rq.Options, options)
	sid := utils.GenerateRandomToken(rq.URL)
	res := &Res{
		Code: http.StatusOK,
		Msg:  sid,
	}
	*scans = append(*scans, sid)
	if options.Scan == nil {
		options.Scan = make(map[string]model.Scan)
	}
	go startAPIScan(rq.URL, rq.Options, *options, sid)

	return respondJSONorJSONP(c, http.StatusOK, res, options)
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
	return respondJSONorJSONP(c, http.StatusOK, Res{Code: 200, Msg: "All scans deleted"}, options)
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
		return respondJSONorJSONP(c, http.StatusNotFound, Res{Code: 404, Msg: "Scan ID not found"}, options)
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

	return respondJSONorJSONP(c, http.StatusOK, Res{Code: 200, Msg: "Scan deleted successfully"}, options)
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
