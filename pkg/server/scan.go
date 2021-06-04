package server

import (
	"github.com/hahwul/dalfox/v2/pkg/model"
	scan "github.com/hahwul/dalfox/v2/pkg/scanning"
)

// ScanFromAPI is scanning dalfox with REST API
// @Summary scan
// @Description add dalfox scan
// @Accept  json
// @Produce  json
// @Param data body Req true "json data"
// @Success 200 {object} Res
// @Router /scan [post]
func ScanFromAPI(url string, rqOptions model.Options, options model.Options, sid string) {
	rqOptions.Scan = options.Scan
	rqOptions.SpinnerObject = options.SpinnerObject
	rqOptions.AuroraObject = options.AuroraObject
	rqOptions.StartTime = options.StartTime
	_, _ = scan.Scan(url, rqOptions, sid)
}

// GetScan is get scan information
// @Summary scan
// @Description get scan info
// @Accept  json
// @Produce  json
// @Param scanid path string true "scan id"
// @Success 200 {object} Res
// @Router /scan/{scanid} [get]
func GetScan(sid string, options model.Options) model.Scan {
	return options.Scan[sid]
}

// GetScans is list of scan
// @Summary scan
// @Description show scan list
// @Accept  json
// @Produce  json
// @Success 200 {array} string
// @Router /scans [get]
func GetScans() {

}
