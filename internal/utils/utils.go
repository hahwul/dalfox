package utils

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"

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

// notScanningType defines Content-Types that should not be scanned for XSS.
// Note: XML types (application/xml, text/xml, image/svg+xml) are intentionally
// excluded because they are valid XSS vectors (e.g. SVG can contain <script> tags).
var notScanningType = map[string]struct{}{
	"application/json":         {},
	"application/javascript":   {},
	"application/x-javascript": {},
	"application/octet-stream": {},
	"text/javascript":          {},
	"text/plain":               {},
	"text/css":                 {},
	"text/csv":                 {},
	"image/jpeg":               {},
	"image/png":                {},
	"image/bmp":                {},
	"image/gif":                {},
	"application/rss+xml":      {},
	"application/atom+xml":     {},
	"application/pdf":          {},
	"application/zip":          {},
}

// IsAllowType is checking content-type
func IsAllowType(contentType string) bool {
	for n := range notScanningType {
		if strings.Contains(contentType, n) {
			return false
		}
	}
	return true
}

// jsonpPattern matches JSONP callback patterns like: callbackName({...}) or jQuery123({...})
var jsonpPattern = regexp.MustCompile(`^\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(`)

// IsJSONBody checks if the response body is valid JSON or JSONP content.
// Uses json.Valid() for strict validation to avoid suppressing real XSS findings
// on HTML responses that incidentally start with '{' or '['.
func IsJSONBody(body string) bool {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	// Standard JSON: validate with json.Valid
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return json.Valid([]byte(trimmed))
	}
	// JSONP: extract content inside callback and validate the inner JSON
	if jsonpPattern.MatchString(trimmed) {
		// Strip optional trailing semicolon
		content := strings.TrimRight(trimmed, ";")
		content = strings.TrimSpace(content)
		if len(content) == 0 || content[len(content)-1] != ')' {
			return false
		}
		start := strings.Index(content, "(")
		if start == -1 {
			return false
		}
		inner := strings.TrimSpace(content[start+1 : len(content)-1])
		return json.Valid([]byte(inner))
	}
	return false
}

// GenerateTerminalWidthLine generates a string that fills the terminal width with the specified character
func GenerateTerminalWidthLine(char string) string {
	width := GetTerminalWidth() - 5
	return strings.Repeat(char, width)
}

// GetTerminalWidth returns the width of the terminal
func GetTerminalWidth() int {
	width := 80 // default width
	if term.IsTerminal(int(os.Stdout.Fd())) {
		termWidth, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil && termWidth > 0 {
			width = termWidth
		}
	}

	return width
}
