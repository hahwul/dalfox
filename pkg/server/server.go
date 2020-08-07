package server

import (
	"net/http"
	"time"

	"github.com/swaggo/echo-swagger"
	_ "github.com/hahwul/dalfox/pkg/server/docs"
	printing "github.com/hahwul/dalfox/pkg/printing"
	"github.com/tylerb/graceful"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/echo/v4"
)

// @title DalFox API
// @version 1.0
// @description This is a dalfox api swagger
// @termsOfService http://swagger.io/terms/

// @license.name MIT
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:6664
// @BasePath /

func RunAPIServer(optionsStr map[string]string, optionsBool map[string]bool) {
	e := echo.New()
	e.Server.Addr = ":6664"
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "",
		ContentTypeNosniff:    "",
		XFrameOptions:         "",
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self'",
	}))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))
	e.GET("/health", func(c echo.Context) error {
		r := &Res{
			Code: 200,
			Msg: "ok",
		}
		return c.JSON(http.StatusOK,r)
	})
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/scans", func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	})
	e.GET("/scan/:sid", func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	})
	e.POST("/scan", func(c echo.Context) error {
		rq := new(Req)
		if err := c.Bind(rq); err != nil{
			r := &Res{
				Code: 500,
				Msg: "Parameter Bind error",
			}
			return c.JSON(http.StatusInternalServerError,r)
		}
		sid := GenerateRandomToken(rq.URL)
		r := &Res{
			Code: 200,
			Msg: sid,
		}
		go ScanFromAPI(rq.URL, rq.Options, optionsStr,optionsBool)
		return c.JSON(http.StatusOK,r)
	})
	printing.DalLog("SYSTEM", "Listen "+e.Server.Addr, optionsStr)
	graceful.ListenAndServe(e.Server, 5*time.Second)
}
