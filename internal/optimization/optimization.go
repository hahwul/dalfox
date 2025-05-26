package optimization

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hahwul/dalfox/v2/internal/har"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

// GenerateNewRequest is make http.Cilent
func GenerateNewRequest(url, body string, options model.Options) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	req = har.AddMessageIDToRequest(req)
	// Add the Accept header like browsers do.
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	if options.Data != "" {
		d := []byte(body)
		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(d))
		req = har.AddMessageIDToRequest(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(options.Header) > 0 {
		for _, v := range options.Header {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				req.Header.Set(h[0], h[1])
			}
		}
	}
	if options.Cookie != "" {
		req.Header.Set("Cookie", options.Cookie)
	}
	if options.UserAgent != "" {
		req.Header.Set("User-Agent", options.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.Method != "" {
		req.Method = options.Method
	}
	if options.CookieFromRaw != "" {
		rawFile := options.CookieFromRaw
		rF, err := os.Open(rawFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			rd := bufio.NewReader(rF)
			rq, err := http.ReadRequest(rd)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			} else {
				req.Header.Set("Cookie", GetRawCookie(rq.Cookies()))
			}
		}
	}
	return req
}

// GetRawCookie gets cookie from raw request
func GetRawCookie(cookies []*http.Cookie) string {
	var rawCookies []string
	for _, c := range cookies {
		e := fmt.Sprintf("%s=%s", c.Name, c.Value)
		rawCookies = append(rawCookies, e)
	}
	return strings.Join(rawCookies, "; ")
}

// MakeHeaderQuery is generate http query with custom header
func MakeHeaderQuery(target, hn, hv string, options model.Options) (*http.Request, map[string]string) {
	tempMap := make(map[string]string)
	tempMap["type"] = "toBlind"
	tempMap["payload"] = hv
	tempMap["param"] = "thisisheadertesting"
	req, _ := http.NewRequest("GET", target, nil)
	req = har.AddMessageIDToRequest(req)
	if options.Data != "" {
		d := []byte("")
		req, _ = http.NewRequest("POST", target, bytes.NewBuffer(d))
		req = har.AddMessageIDToRequest(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(options.Header) > 0 {
		for _, v := range options.Header {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				req.Header.Set(h[0], h[1])
			}
		}
	}

	if options.Cookie != "" {
		req.Header.Set("Cookie", options.Cookie)
	}
	if options.UserAgent != "" {
		req.Header.Set("User-Agent", options.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}
	if options.Method != "" {
		req.Method = options.Method
	}
	req.Header.Set(hn, hv)
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
	var tempParamBody string
	if options.Data == "" {
		tempParam = u.RawQuery // ---> GET
	} else {
		tempParam = u.RawQuery       // ---> GET
		tempParamBody = options.Data // ---> POST
	}

	paramList, _ := url.ParseQuery(tempParam)
	paramListBody, _ := url.ParseQuery(tempParamBody)

	// Handle jsonBody case first, as it constructs the request differently.
	if pAction == "jsonBody" {
		// payload here is the marshalled JSON string. param is the json_path (for logging/metadata).
		// ptype is "inJSON". pEncode is NaN.
		var req *http.Request
		var err error
		// Use options.Method; default to POST if not specified and data is present, or allow GET if specified.
		method := options.Method
		if method == "GET" && payload != "" {
			// Sending a body with GET is unusual but possible. If user explicitly sets GET, respect it.
			// However, if method is not set or is GET by default, and we have a JSON body, POST is more appropriate.
			// For now, let's assume if method is GET, body should not be sent unless explicitly handled by server.
			// This part might need refinement based on desired behavior for GET + JSON body.
			// A common practice is to use POST/PUT/PATCH for requests with bodies.
			// If options.Method is not set (i.e. is default "GET"), and we have a JSON body, switch to "POST".
			if options.Method == "GET" || options.Method == "" { // Default method is GET
				method = "POST" // Change to POST for JSON body if not explicitly set otherwise
			}
		}


		req, err = http.NewRequest(method, u.String(), strings.NewReader(payload))
		if err != nil {
			// Handle error, e.g., log and return nil
			// printing.DalLog("ERROR", "Failed to create new HTTP request for JSON body: "+err.Error(), options)
			return nil, tempMap // Or some other error indication
		}
		req = har.AddMessageIDToRequest(req)
		req.Header.Set("Content-Type", "application/json")

		// Apply other options like custom headers, user-agent, cookies
		if len(options.Header) > 0 {
			for _, v := range options.Header {
				h := strings.Split(v, ": ")
				if len(h) > 1 {
					// Avoid overwriting Content-Type if it was manually set in options.Header to application/json already
					if strings.ToLower(h[0]) == "content-type" && h[1] == "application/json" {
						continue
					}
					req.Header.Set(h[0], h[1])
				}
			}
		}
		if options.Cookie != "" {
			req.Header.Set("Cookie", options.Cookie)
		}
		if options.UserAgent != "" {
			req.Header.Set("User-Agent", options.UserAgent)
		} else {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
		}
		// CookieFromRaw is handled by GenerateNewRequest, might need to integrate if used with jsonBody
		// For now, assuming it's less common for pure JSON APIs compared to direct Cookie header.

		tempMap["original_payload_for_request_body"] = payload // Storing the actual body for clarity if needed
		return req, tempMap
	}

	//What we should do to the payload?
	switch tempMap["encode"] {
	case "urlEncode":
		payload = UrlEncode(payload)
		break

	case "urlDoubleEncode":
		payload = (UrlEncode(payload))
		break

	case "htmlEncode":
		payload = template.HTMLEscapeString(payload)
		break

	default:
		break
	}

	// We first check if the parameter exist and then "append or replace" the value
	if strings.Contains(ptype, "FORM") {
		if val, ok := paramListBody[tempMap["param"]]; ok {
			if tempMap["action"] == "toAppend" {
				paramListBody[tempMap["param"]][0] = val[0] + payload
			} else { //toReplace lies here
				paramListBody[tempMap["param"]][0] = payload
			}
		} else {
			//if the parameter doesn't exist, is added.
			paramListBody.Add(tempMap["param"], payload)
		}

		var rst *http.Request
		rst = GenerateNewRequest(u.String(), paramListBody.Encode(), options)
		return rst, tempMap
	} else {
		// PA-URL
		if val, ok := paramList[tempMap["param"]]; ok {
			if tempMap["action"] == "toAppend" {
				paramList[tempMap["param"]][0] = val[0] + payload
			} else { //toReplace lies here
				paramList[tempMap["param"]][0] = payload
			}
		} else {
			//if the parameter doesn't exist, is added.
			paramList.Add(tempMap["param"], payload)
		}

		var rst *http.Request
		u.RawQuery = paramList.Encode()
		rst = GenerateNewRequest(u.String(), paramListBody.Encode(), options)
		return rst, tempMap
	}
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
