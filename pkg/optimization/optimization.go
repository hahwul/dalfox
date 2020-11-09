package optimization

import (
	"bytes"
	"fmt"
	"github.com/hahwul/dalfox/pkg/model"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// GenerateNewRequest is make http.Cilent
func GenerateNewRequest(url, payload string, options model.Options) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	if options.Data != "" {
		d := []byte(payload)
		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(d))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	if options.Header != "" {
		h := strings.Split(options.Header, ": ")
		if len(h) > 1 {
			req.Header.Add(h[0], h[1])
		}
	}
	if options.Cookie != "" {
		req.Header.Add("Cookie", options.Cookie)
	}
	if options.UserAgent != "" {
		req.Header.Add("User-Agent", options.UserAgent)
	} else {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.Method != "" {
		req.Method = options.Method
	}
	return req
}

// MakeHeaderQuery is generate http query with custom header
func MakeHeaderQuery(target, hn, hv string, options model.Options) (*http.Request, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = "toBlind"
	tempMap["payload"] = hv
	tempMap["param"] = "thisisheadertesting"
	req, _ := http.NewRequest("GET", target, nil)
	if options.Data != "" {
		d := []byte("")
		req, _ = http.NewRequest("POST", target, bytes.NewBuffer(d))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	if options.Header != "" {
		h := strings.Split(options.Header, ": ")
		if len(h) > 1 {
			req.Header.Add(h[0], h[1])
		}
	}
	if options.Cookie != "" {
		req.Header.Add("Cookie", options.Cookie)
	}
	if options.UserAgent != "" {
		req.Header.Add("User-Agent", options.UserAgent)
	} else {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.Method != "" {
		req.Method = options.Method
	}
	req.Header.Add(hn, hv)
	return req, tempMap
}

// MakeRequestQuery is generate http query with custom parameters
func MakeRequestQuery(target, param, payload, ptype string, pAction string, pEncode string, options model.Options) (*http.Request, map[string]string) {
	
	tempMap := make(map[string]string)
	tempMap["type"] = ptype
	tempMap["action"] = pAction
	tempMap["encode"] = pEncode
	tempMap["payload"] = payload
	tempMap["param"] = param

	u, _ := url.Parse(target)

	var tempParam string
	if(options.Data == ""){
		tempParam = u.RawQuery				// ---> GET
	} else{
		tempParam = options.Data			// ---> POST
	}	
	
	paramList, _ := url.ParseQuery(tempParam)

	//What we should do to the payload?
	switch tempMap["encode"]{
		case "urlEncode":
			payload = UrlEncode(payload)
			break

		case "htmlEncode":
			payload = template.HTMLEscapeString(payload)
			break
			
		default:
			break	
	}

	// We first check if the parameter exist and then "append or replace" the value
	if val, ok := paramList[tempMap["param"]]; ok {
		if(tempMap["action"] == "toAppend"){
			paramList[tempMap["param"]][0] = val[0] + payload
		}else { //toReplace lies here
			paramList[tempMap["param"]][0] = payload
		}			
	}else{
		//if the parameter doesn't exist, is added.
		paramList.Add(tempMap["param"], payload)
	}				
	
	var rst *http.Request
	if(options.Data == ""){
		u.RawQuery = paramList.Encode()
		rst = GenerateNewRequest(u.String(), "", options)
	}else{
		rst = GenerateNewRequest(u.String(), paramList.Encode(), options)
	}
		
	return rst, tempMap
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
