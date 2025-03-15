package optimization

import (
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// CheckInspectionParam is Checking Inspection
func CheckInspectionParam(options model.Options, k string) bool {
	uniqParams := make(map[string]struct{}, len(options.UniqParam))
	for _, param := range options.UniqParam {
		uniqParams[param] = struct{}{}
	}

	ignoreParams := make(map[string]struct{}, len(options.IgnoreParams))
	for _, param := range options.IgnoreParams {
		ignoreParams[param] = struct{}{}
	}

	if len(uniqParams) > 0 {
		_, exists := uniqParams[k]
		return exists
	}

	if len(ignoreParams) > 0 {
		_, exists := ignoreParams[k]
		return !exists
	}

	return true
}
