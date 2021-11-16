package scanning

import (
	"strconv"
	"strings"
)

//CodeView is showing reflected code function
func CodeView(resbody, pattern string) string {
	var code string
	if resbody == "" {
		return ""
	}
	bodyarr := strings.Split(resbody, "\n")
	for bk, bv := range bodyarr {
		if strings.Contains(bv, pattern) {
			max := len(bv)
			if max > 80 {
				index := strings.Index(bv, pattern)
				if index < 20 {
					code = code + strconv.Itoa(bk+1) + " line:  " + bv[:80] + "\n    "
				} else {
					if max < index+60 {
						code = code + strconv.Itoa(bk+1) + " line:  " + bv[index-20:max] + "\n    "
					} else {
						code = code + strconv.Itoa(bk+1) + " line:  " + bv[index-20:index+60] + "\n    "
					}
				}
			} else {
				code = code + strconv.Itoa(bk+1) + " line:  " + bv + "\n    "
			}
		}
	}
	if len(code) > 4 {
		return code[:len(code)-5]
	}
	return code
}
