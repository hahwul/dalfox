package printing

import "strings"

// CheckToShowPoC is check logic for --only-poc flag
func CheckToShowPoC(patterns string) (bool, bool, bool) {
	g := false
	r := false
	v := false
	sp := strings.Split(patterns, ",")
	for _, pattern := range sp {
		switch pattern {
		case "g":
			g = true
		case "r":
			r = true
		case "v":
			v = true
		}
	}
	return g, r, v
}
