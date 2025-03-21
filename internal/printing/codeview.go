package printing

import (
	"strconv"
	"strings"
)

// CodeView is showing reflected code function
func CodeView(resbody, pattern string) string {
	if resbody == "" {
		return ""
	}

	var builder strings.Builder
	bodyarr := strings.Split(resbody, "\n")

	for bk, bv := range bodyarr {
		if strings.Contains(bv, pattern) {
			index := strings.Index(bv, pattern)
			start := 0
			if index > 20 {
				start = index - 20
			}
			end := start + 80
			if end > len(bv) {
				end = len(bv)
			}

			builder.WriteString(strconv.Itoa(bk + 1))
			builder.WriteString(" line:  ")
			builder.WriteString(bv[start:end])
			builder.WriteString("\n    ")
		}
	}

	code := builder.String()
	if len(code) > 4 {
		return code[:len(code)-5]
	}
	return code
}
