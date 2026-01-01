package optimization

import (
	"net/url"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// IsOutOfScope checks if a URL's host matches any out-of-scope pattern.
// Supports wildcard matching:
//   - "stg.example.com" = exact match only
//   - "*.stg.example.com" = matches subdomains (api.stg.example.com, devapi.stg.example.com)
func IsOutOfScope(options model.Options, targetURL string) bool {
	if len(options.OutOfScope) == 0 {
		return false
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		// Treat malformed URLs as out-of-scope for safety
		return true
	}

	host := strings.ToLower(parsedURL.Hostname())
	// Handle URLs without scheme - url.Parse puts them in Path with empty Host
	if host == "" && parsedURL.Path != "" {
		parsedURL, err = url.Parse("http://" + targetURL)
		if err != nil {
			return true
		}
		host = strings.ToLower(parsedURL.Hostname())
	}
	for _, pattern := range options.OutOfScope {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if matchDomainPattern(host, pattern) {
			return true
		}
	}
	return false
}

// matchDomainPattern checks if host matches the pattern.
// Pattern "*.example.com" matches "sub.example.com" but not "example.com"
// Pattern "example.com" matches only "example.com" exactly
func matchDomainPattern(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

// FilterOutOfScopeTargets removes out-of-scope URLs from a target list
func FilterOutOfScopeTargets(options model.Options, targets []string) []string {
	if len(options.OutOfScope) == 0 {
		return targets
	}

	filtered := make([]string, 0, len(targets))
	for _, target := range targets {
		if !IsOutOfScope(options, target) {
			filtered = append(filtered, target)
		}
	}
	return filtered
}
