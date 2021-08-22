package optimization

import (
	"github.com/hahwul/dalfox/v2/pkg/model"
)

func CheckUniqParam(options model.Options, k string) bool {
	if len(options.UniqParam) > 0 {
		for _, selectedParam := range options.UniqParam {
			if selectedParam == k {
				return true
			}
		}
		return false
	}
	return true
}
