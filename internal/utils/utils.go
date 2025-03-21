package utils

import (
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func IndexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found
}

func DuplicatedResult(result []model.PoC, rst model.PoC) bool {
	types := make(map[string]struct{}, len(result))
	for _, v := range result {
		types[v.Type] = struct{}{}
	}
	_, exists := types[rst.Type]
	return exists
}

func ContainsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	i := strings.Split(item, "(")[0]
	_, ok := set[i]
	return ok
}

func CheckPType(str string) bool {
	return !strings.Contains(str, "toBlind") && !strings.Contains(str, "toGrepping")
}

// IsAllowType is checking content-type
func IsAllowType(contentType string) bool {
	notScanningType := map[string]struct{}{
		"application/json":       {},
		"application/javascript": {},
		"text/javascript":        {},
		"text/plain":             {},
		"text/css":               {},
		"image/jpeg":             {},
		"image/png":              {},
		"image/bmp":              {},
		"image/gif":              {},
		"application/rss+xml":    {},
	}

	for n := range notScanningType {
		if strings.Contains(contentType, n) {
			return false
		}
	}
	return true
}
