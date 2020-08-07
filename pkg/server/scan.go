package server 

import (
	. "github.com/hahwul/dalfox/pkg/scanning"
)

// ScanFromAPI is scanning dalfox with REST API
func ScanFromAPI(url string, options map[string]interface{}, optionsStr map[string]string, optionsBool map[string]bool){
	Scan(url,optionsStr,optionsBool)
}
