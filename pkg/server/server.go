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
	e := setupEchoServer(options, &scans)
	printing.DalLog("SYSTEM", "Listen "+e.Server.Addr, options)
	graceful.ListenAndServe(e.Server, 5*time.Second)
}

func setupEchoServer(options model.Options, scans *[]string) *echo.Echo {
	e := echo.New()
	options.IsAPI = true
	e.Server.Addr = options.ServerHost + ":" + strconv.Itoa(options.ServerPort)
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
		return scanHandler(c, scans, options)
	})
	e.POST("/scan", func(c echo.Context) error {
		return postScanHandler(c, scans, options)
	})
	return e
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

func scanHandler(c echo.Context, scans *[]string, options model.Options) error {
	sid := c.Param("sid")
	if !contains(*scans, sid) {
		r := &Res{
			Code: 404,
			Msg:  "Not found scanid",
		}
		return c.JSON(http.StatusNotFound, r)
	}
	r := &Res{
		Code: 200,
	}
	scan := GetScan(sid, options)
	if len(scan.URL) == 0 {
		r.Msg = "scanning"
	} else {
		r.Msg = "finish"
		r.Data = scan.Results
	}
	return c.JSON(http.StatusOK, r)
}

func postScanHandler(c echo.Context, scans *[]string, options model.Options) error {
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
	go ScanFromAPI(rq.URL, rq.Options, options, sid)
	return c.JSON(http.StatusOK, r)
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
