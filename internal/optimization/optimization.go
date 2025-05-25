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
	"encoding/json" // Added for JSON operations
	"strconv"      // Added for string conversions (e.g., path index)
	"io"           // Added for io.ReadAll and io.NopCloser

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
// The old complex version has been removed. This is the wrapper version.
func MakeHeaderQuery(target, hn, hv string, options model.Options) (*http.Request, map[string]string) {
	// This function is now a wrapper for MakeRequestQuery with ParamTypeHeader
	return MakeRequestQuery(target, hn, hv, "toBlind-"+model.ParamTypeHeader, "toReplace", "NaN", options, model.ParamTypeHeader)
}

// MakeRequestQuery is generate http query with custom parameters
func MakeRequestQuery(targetURLStr, paramName, payloadValue, ptypeString string, pAction string, pEncode string, options model.Options, actualParamType string) (*http.Request, map[string]string) {
	metaData := make(map[string]string)
	metaData["type"] = ptypeString    // e.g. "inHTML-QUERY", "toBlind-HEADER"
	metaData["action"] = pAction      // "toAppend" or "toReplace"
	metaData["encode"] = pEncode      // "urlEncode", "htmlEncode", "NaN"
	metaData["payload"] = payloadValue // Original payload before encoding
	metaData["param"] = paramName

	// Apply encoding to the payloadValue first
	encodedPayload := payloadValue
	switch pEncode {
	case "urlEncode":
		encodedPayload = UrlEncode(payloadValue)
	case "urlDoubleEncode":
		encodedPayload = UrlEncode(UrlEncode(payloadValue))
	case "htmlEncode":
		encodedPayload = template.HTMLEscapeString(payloadValue)
	}

	// Base request using GenerateNewRequest (which handles method, initial data, headers from options)
	// For body modifications (JSON, Form), options.Data is the base. For others, it might be empty.
	// GenerateNewRequest internally sets Content-Type for options.Data if it's POST.
	// We might need to override Content-Type for JSON.
	
	// For path, query, fragment, header, cookie, the body of the base request is typically options.Data or nil.
	// For body_form, body_json, options.Data is the base that gets modified.
	
	baseRequestBody := options.Data
	// If we are injecting into body form or json, and pAction is "toReplace" for a key,
	// the concept of "appending" to options.Data doesn't quite fit if options.Data is a full structure.
	// This needs careful handling. For now, GenerateNewRequest uses options.Data as is.

	req := GenerateNewRequest(targetURLStr, baseRequestBody, options)
	if req == nil {
		return nil, metaData // Should not happen if targetURLStr is valid
	}
	
	currentURL, err := url.Parse(req.URL.String()) // Use req.URL as it might have been modified by GenerateNewRequest
	if err != nil {
		return req, metaData // Return base request if URL parsing fails
	}

	switch actualParamType {
	case model.ParamTypeQuery:
		q := currentURL.Query()
		if pAction == "toAppend" && q.Has(paramName) {
			q.Set(paramName, q.Get(paramName)+encodedPayload)
		} else {
			q.Set(paramName, encodedPayload)
		}
		currentURL.RawQuery = q.Encode()
		req.URL = currentURL

	case model.ParamTypeFragment:
		// Fragment handling is tricky as it can be a simple string or query-like.
		// Assuming query-like fragment if pAction is involved with a specific paramName.
		fragQuery, _ := url.ParseQuery(currentURL.Fragment)
		if pAction == "toAppend" && fragQuery.Has(paramName) {
			fragQuery.Set(paramName, fragQuery.Get(paramName)+encodedPayload)
		} else {
			fragQuery.Set(paramName, encodedPayload)
		}
		currentURL.Fragment = fragQuery.Encode()
		req.URL = currentURL
	
	case model.ParamTypeHeader:
		// Note: GenerateNewRequest already sets headers from options.
		// This will overwrite if paramName is one of those, or add a new one.
		if pAction == "toAppend" && req.Header.Get(paramName) != "" {
			req.Header.Set(paramName, req.Header.Get(paramName)+encodedPayload)
		} else {
			req.Header.Set(paramName, encodedPayload)
		}

	case model.ParamTypeCookie:
		// Cookies are managed as a single header string.
		// We need to parse, modify, and reconstruct.
		var newCookies []string
		existingCookies := req.Cookies() // Parses from req.Header["Cookie"]
		found := false
		for _, cookie := range existingCookies {
			if cookie.Name == paramName {
				found = true
				if pAction == "toAppend" {
					cookie.Value += encodedPayload
				} else {
					cookie.Value = encodedPayload
				}
			}
			newCookies = append(newCookies, cookie.Name+"="+cookie.Value)
		}
		if !found {
			newCookies = append(newCookies, paramName+"="+encodedPayload)
		}
		req.Header.Set("Cookie", strings.Join(newCookies, "; "))

	case model.ParamTypeBodyForm:
		// Assumes req.Body was initially set from options.Data by GenerateNewRequest if method is POST.
		// And options.Data is x-www-form-urlencoded string.
		// We need to parse, modify, and reconstruct the body.
		var formValues url.Values
		var err error
		if req.Body != nil {
			bodyBytes, _ :=ReadAll(req.Body)
			req.Body.Close() // Close the original body
			req.Body = NopCloser(bytes.NewBuffer(bodyBytes)) // Replace with a new reader for future reads if any (e.g. by HAR)
			
			formValues, err = url.ParseQuery(string(bodyBytes))
			if err != nil { // If parsing original body fails, start fresh
				formValues = make(url.Values)
			}
		} else {
			formValues = make(url.Values)
		}
		
		if pAction == "toAppend" && formValues.Has(paramName) {
			formValues.Set(paramName, formValues.Get(paramName)+encodedPayload)
		} else {
			formValues.Set(paramName, encodedPayload)
		}
		newBody := formValues.Encode()
		req.Body = NopCloser(strings.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		// Ensure Content-Type is set, GenerateNewRequest might do this if options.Data is present.
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	
	case model.ParamTypeBodyJSON:
		// Assumes options.Data contains the original JSON string.
		var jsonData map[string]interface{}
		if options.Data != "" {
			err := json.Unmarshal([]byte(options.Data), &jsonData)
			if err != nil {
				// Handle error: malformed original JSON. Maybe try to inject into a new JSON object?
				// For now, if original JSON is malformed, we might not be able to proceed safely.
				// Or, create a new JSON object with the single key.
				jsonData = make(map[string]interface{})
			}
		} else {
			jsonData = make(map[string]interface{})
		}

		// The encodedPayload is the XSS vector (e.g. <svg onload=alert(1)>)
		// It needs to be a valid JSON string value when placed in the map.
		// json.Marshal will handle the JSON string escaping of encodedPayload.
		if pAction == "toAppend" {
			if existingVal, ok := jsonData[paramName]; ok {
				if existingStr,isStr := existingVal.(string); isStr {
					jsonData[paramName] = existingStr + encodedPayload
				} else {
					// appending to non-string, convert original to string? or overwrite?
					// for now, overwrite
					jsonData[paramName] = encodedPayload 
				}
			} else {
				jsonData[paramName] = encodedPayload
			}
		} else { // toReplace
			jsonData[paramName] = encodedPayload
		}
		
		newBodyBytes, err := json.Marshal(jsonData)
		if err != nil {
			// Handle error marshalling new JSON
			return req, metaData // return original request or error
		}
		req.Body = NopCloser(bytes.NewBuffer(newBodyBytes))
		req.ContentLength = int64(len(newBodyBytes))
		req.Header.Set("Content-Type", "application/json")

	case model.ParamTypePath:
		// paramName here might be an identifier like "path1" or an original segment value.
		// The actual path segment to replace needs to be determined using metadata
		// (e.g., from paramResult.ReflectedPoint if it stored an index).
		// This is a simplified placeholder. A more robust solution would need
		// the original path structure/template and which part 'paramName' refers to.
		// For now, let's assume paramName is the *exact segment value* to be replaced.
		// This is a limitation of the current approach if path segments are not unique or dynamic.
		
		// A better way: if paramName is "pathN" (e.g. path0, path1), use N as index.
		// Or if ReflectedPoint stored the index.
		pathIndex := -1
		if strings.HasPrefix(paramName, "path") {
			numPart := strings.TrimPrefix(paramName, "path")
			idx, err := strconv.Atoi(numPart)
			if err == nil {
				pathIndex = idx -1 // If "path1" is 0th segment, "path2" is 1st etc.
			}
		}
		
		if pathIndex != -1 {
			// pathParts := strings.Split(currentURL.Path, "/") // Commented out as it's unused
			// pathParts often has an empty string at the start if path starts with /.
			// Adjust index if so. Example: /a/b/c -> ["", "a", "b", "c"]
			// If path is "a/b/c", pathParts is ["a", "b", "c"]
			// We need to be careful with leading/trailing slashes.
			
			// Let's use a more direct approach based on segment index passed via ReflectedPoint in a real scenario.
			// For now, if paramName is "pathN", we try to replace the Nth segment.
			// This is highly simplified.
			
			// Simplified: Replace first occurrence of paramName if it's an actual segment value
			// This is not robust. A real implementation would use segment index.
			// currentURL.Path = strings.Replace(currentURL.Path, paramName, encodedPayload, 1)
			
			// Assuming paramName is an index passed via a convention like "path.0", "path.1" from a future param discovery
			// Or, if the param.Name itself was "0", "1" (index) for path type.
			// For this placeholder, we'll assume `paramName` might be an index string if no other info.
			idx, err := strconv.Atoi(paramName) // This is a weak assumption
			if err == nil && idx >= 0 {
				p := strings.Split(strings.Trim(currentURL.Path, "/"), "/")
				if idx < len(p) {
					p[idx] = encodedPayload
					currentURL.Path = "/" + strings.Join(p, "/")
					if strings.HasSuffix(req.URL.Path, "/") && !strings.HasSuffix(currentURL.Path, "/"){ // Preserve trailing slash if original had it
						currentURL.Path += "/"
					}
				}
			}
			req.URL = currentURL
		}
		// Else: Path param name not in a recognized format for replacement, do nothing to path.

	default:
		// Unknown or unhandled parameter type
		break
	}
	
	// Add HAR message ID to the modified request if it's a new instance or significantly changed
	// GenerateNewRequest already adds it. If we heavily modify req.URL or req.Body, it's still the "same" req object
	// in terms of HAR message ID unless we fully cloned.
	// If req was fully reconstructed (e.g. for path), it might need a new ID.
	// For now, assume GenerateNewRequest's ID is sufficient.

	return req, metaData
}


// ReadAll is a utility function to safely read an io.ReadCloser.
func ReadAll(rc io.ReadCloser) ([]byte, error) {
    if rc == nil {
        return nil, fmt.Errorf("ReadCloser is nil")
    }
    return io.ReadAll(rc) // Changed from ioutil.ReadAll
}

// NopCloser is a utility function to create an io.ReadCloser from an io.Reader.
func NopCloser(r io.Reader) io.ReadCloser {
    return io.NopCloser(r) // Changed from ioutil.NopCloser
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
