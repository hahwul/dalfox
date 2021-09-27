package scanning

import "strings"

// isAllowType is checking content-type
func isAllowType(contentType string) bool {
	notScanningType := []string{
		"application/json",
		"application/javascript",
		"text/javascript",
		"text/plain",
		"text/css",
		"image/jpeg",
		"image/png",
		"image/bmp",
		"image/gif",
		"application/rss+xml",
	}
	for _, n := range notScanningType {
		if strings.Contains(contentType, n) {
			return false
		}
	}
	return true
}
