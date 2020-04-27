package scanning

import "strings"

// isAllowType is checking content-type
func isAllowType(contentType string) bool {
	notScanningType := []string{
		"application/json",
		"text/plain",
	}
	for _, n := range notScanningType {
		if strings.Contains(contentType, n) {
			return false
		}
	}
	return true
}
