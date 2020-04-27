package optimization

import (
	"fmt"
	"html/template"
	"net/url"
	"strings"
)

// MakeRequestQuery is generate http query with custom paramters
func MakeRequestQuery(target, param, payload, ptype string) (string, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["payload"] = payload
	tempMap["param"] = param
	u, _ := url.Parse(target)
	data := u.String()
	tempParam := u.Query()
	data = strings.Replace(data, param+"="+tempParam[param][0], param+"="+tempParam[param][0]+payload, 1)
	tempURL, _ := url.Parse(data)
	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()
	return tempURL.String(), tempMap
}

// MakePathQuery is generate http query with path
func MakePathQuery(target, fakeparam, payload, ptype string) (string, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["payload"] = payload
	tempMap["param"] = fakeparam
	u, err := url.Parse(target)
	if err != nil {
		return target, tempMap
	}
	data := ""
	if u.Path != "" {
		data = u.Scheme + "://" + u.Hostname() + u.Path + ";" + payload
	} else {
		data = u.Scheme + "://" + u.Hostname() + "/" + u.Path + ";" + payload
	}
	tempURL, err := url.Parse(data)
	if err != nil {
		return target, tempMap
	}

	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()

	return tempURL.String(), tempMap
}

// MakeURLEncodeRequestQuery is generate http query with Double URL Encoding
func MakeURLEncodeRequestQuery(target, param, payload, ptype string) (string, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["payload"] = payload
	tempMap["param"] = param
	u, _ := url.Parse(target)
	data := u.String()
	tempParam := u.Query()

	// URL Encoding
	encodedPayload := UrlEncode(UrlEncode(payload))

	data = strings.Replace(data, param+"="+tempParam[param][0], param+"="+tempParam[param][0]+encodedPayload, 1)
	tempURL, _ := url.Parse(data)
	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()
	return tempURL.String(), tempMap
}

// MakeHTMLEncodeRequestQuery is generate http query with Hex Encoding
func MakeHTMLEncodeRequestQuery(target, param, payload, ptype string) (string, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["payload"] = payload
	tempMap["param"] = param
	u, _ := url.Parse(target)
	data := u.String()
	tempParam := u.Query()

	// HTML HEX Encoding
	encodedPayload := template.HTMLEscapeString(payload)

	data = strings.Replace(data, param+"="+tempParam[param][0], param+"="+tempParam[param][0]+encodedPayload, 1)
	tempURL, _ := url.Parse(data)
	tempQuery := tempURL.Query()
	tempURL.RawQuery = tempQuery.Encode()
	return tempURL.String(), tempMap
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

// UrlEncode is custom url encoder for double url encoding
func UrlEncode(s string) (result string) {
	for _, c := range s {
		if c <= 0x7f { // single byte
			result += fmt.Sprintf("%%%X", c)
		} else if c > 0x1fffff { // quaternary byte
			result += fmt.Sprintf("%%%X%%%X%%%X%%%X",
				0xf0+((c&0x1c0000)>>18),
				0x80+((c&0x3f000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else if c > 0x7ff { // triple byte
			result += fmt.Sprintf("%%%X%%%X%%%X",
				0xe0+((c&0xf000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else { // double byte
			result += fmt.Sprintf("%%%X%%%X",
				0xc0+((c&0x7c0)>>6),
				0x80+(c&0x3f),
			)
		}
	}

	return result
}
