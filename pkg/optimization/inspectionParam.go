package optimization

import (
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// CheckInspectionParam is Checking Inspection
func CheckInspectionParam(options model.Options, k string) bool {
	if len(options.UniqParam) > 0 {
		for _, selectedParam := range options.UniqParam {
			if selectedParam == k {
				return true
			}
		}
		return false
	}
	if len(options.IgnoreParams) > 0 {
		for _, ignoreParam := range options.IgnoreParams {
			if ignoreParam == k {
				return false
			}
		}
	}
	return true
}
