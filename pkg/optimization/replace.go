package optimization

import (
	"strings"

	model "github.com/hahwul/dalfox/v2/pkg/model"
)

// SetPayloadValue is change alert/prompt/conrifm value and type
func SetPayloadValue(payloads []string, options model.Options) []string {
	var result []string
	catype := strings.Split(options.CustomAlertType, ",")
	for _,payload := range payloads {
		for _,k := range catype {
			if k == "none" {
				temp := strings.ReplaceAll(payload, "DALFOX_ALERT_VALUE", options.CustomAlertValue)
				result = append(result, temp)
			} else if k == "str" {
				temp := strings.ReplaceAll(payload, "DALFOX_ALERT_VALUE", "\""+options.CustomAlertValue+"\"")
				result = append(result, temp)
				temp = strings.ReplaceAll(payload, "DALFOX_ALERT_VALUE", "'"+options.CustomAlertValue+"'")
				result = append(result, temp)
			}
		}
	}
	return result
}
