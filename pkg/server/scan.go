package server 

import (
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
func ScanFromAPI(url string, options map[string]interface{}, optionsStr map[string]string, optionsBool map[string]bool){
	scan.Scan(url,optionsStr,optionsBool)
}
