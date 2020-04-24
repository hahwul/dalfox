package optimization

import (
	"net/url"
	"strings"
)

// MakeRequestQuery is generate http query with custom paramters
func MakeRequestQuery(target, param, payload string) string {
	u, _ := url.Parse(target)
	data := u.String()
	tempParam := u.Query()
	//fmt.Println(tempParam[param])
	data = strings.Replace(data, param+"="+tempParam[param][0], param+"="+tempParam[param][0]+payload, 1)
	tempURL, _ := url.Parse(data)
	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()
	return tempURL.String()
}

// MakePathQuery is generate http query with path
func MakePathQuery(target, payload string) string {
	u, _ := url.Parse(target)
	data := ""
	if u.Path != "" {
		data = u.Scheme + "://" + u.Hostname() + u.Path + ";" + payload
	} else {
		data = u.Scheme + "://" + u.Hostname() + "/" + u.Path + ";" + payload
	}
	tempURL, _ := url.Parse(data)
	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()
	return tempURL.String()
}

// Optimization is remove payload included badchar
func Optimization(payload string, badchars []string) bool {
	for _, v := range badchars {
		if strings.Contains(payload, v) {
			return false
		}
	}
	return true
}
