package scanning

import "net/url"

// makeTargetSlice is make slice for multicast option
func makeTargetSlice(targets []string) map[string][]string {
	result := make(map[string][]string)
	for _, target := range targets {
		t, err := url.Parse(target)
		if err == nil {
			hostname := t.Hostname()
			result[hostname] = append(result[hostname], target)
		}
	}
	return result
}
