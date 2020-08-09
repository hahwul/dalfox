package server

import (
	"github.com/hahwul/dalfox/pkg/model"
	scan "github.com/hahwul/dalfox/pkg/scanning"
)

// ScanFromAPI is scanning dalfox with REST API
// @Summary scan
// @Description add dalfox scan
// @Accept  json
// @Produce  json
// @Param data body Req true "json data"
// @Success 200 {object} Res
// @Router /scan [post]
func ScanFromAPI(url string, rqOptions map[string]interface{}, options model.Options){
	scan.Scan(url,options)
}
