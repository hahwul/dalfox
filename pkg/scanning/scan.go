package scanning

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/utils"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/report"
	"github.com/hahwul/dalfox/v2/pkg/model"
	voltFile "github.com/hahwul/volt/file"
)

const (
	NaN             = "NaN"
	urlEncode       = "urlEncode"
	urlDoubleEncode = "urlDoubleEncode"
	htmlEncode      = "htmlEncode"
)

var (
	scanObject model.Scan
	s          = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
)

// Scan is main scanning function
func Scan(target string, options model.Options, sid string) (model.Result, error) {
	var scanResult model.Result
	options.ScanResult = scanResult
	scanResult.StartTime = time.Now()

	// Initialize options.Scan map if it doesn't exist
	if options.Scan == nil {
		options.Scan = make(map[string]model.Scan)
	}

	// Initialize spinner
	if !(options.Silence || options.NoSpinner) {
		initializeSpinner(options)
	}
	scanObject := model.Scan{
		ScanID: sid,
		URL:    target,
	}
	if !(options.Silence && options.MulticastMode) {
		logStartScan(target, options, sid)
	}
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	parsedURL, err := url.Parse(target)
	if err != nil {
		printing.DalLog("SYSTEM", "Unable to parse URL: "+target+". Please ensure it is a valid URL.", options)
		return scanResult, err
	}
	treq := optimization.GenerateNewRequest(target, "", options)
	if treq == nil {
		return scanResult, fmt.Errorf("failed to generate initial request")
	}
	client := createHTTPClient(options)
	tres, err := client.Do(treq)
	if err != nil {
		msg := fmt.Sprintf("Request to %s failed: %v", target, err)
		printing.DalLog("ERROR", msg, options)
		return scanResult, err
	}
	if options.IgnoreReturn != "" {
		if shouldIgnoreReturn(tres.StatusCode, options.IgnoreReturn) {
			printing.DalLog("SYSTEM", "Skipping URL "+target+" due to ignore-return option", options)
			return scanResult, nil
		}
	}
	defer tres.Body.Close()
	body, err := io.ReadAll(tres.Body)
	if err != nil {
		return scanResult, err
	}
	printing.DalLog("SYSTEM", "Valid target [ code:"+strconv.Itoa(tres.StatusCode)+" / size:"+strconv.Itoa(len(body))+" ]", options)

	// Discovery phase
	var policy map[string]string
	var pathReflection map[int]string
	var params map[string]model.ParamResult
	if !options.SkipDiscovery {
		policy, pathReflection, params = performDiscovery(target, options, rl)
	} else {
		printing.DalLog("SYSTEM", "Skipping discovery phase as requested with --skip-discovery", options)
		policy = make(map[string]string)
		pathReflection = make(map[int]string)
		params = make(map[string]model.ParamResult)
		if len(options.UniqParam) == 0 {
			printing.DalLog("ERROR", "--skip-discovery requires parameters to be specified with -p flag (e.g., -p username)", options)
			return scanResult, fmt.Errorf("--skip-discovery requires parameters to be specified with -p flag")
		}
		for _, paramName := range options.UniqParam {
			if paramName != "" {
				params[paramName] = model.ParamResult{
					Name:      paramName,
					Type:      "URL",
					Reflected: true,
					Chars:     payload.GetSpecialChar(),
				}
			}
		}
		policy["Content-Type"] = "text/html"
		printing.DalLog("INFO", "Discovery phase and content-type checks skipped. Testing with "+strconv.Itoa(len(params))+" parameters from -p flag", options)
	}

	// Save discovery results
	logPolicyAndPathReflection(policy, options, parsedURL)
	for k, v := range params {
		printing.DalLog("INFO", "Reflected "+k+" param => "+strings.Join(v.Chars, "  "), options)
		printing.DalLog("CODE", v.ReflectedCode, options)
		scanResult.Params = append(scanResult.Params, v)
	}

	// Get payloads and perform scanning
	if !options.OnlyDiscovery {
		vStatus := make(map[string]bool)
		for k := range params {
			vStatus[k] = false
		}
		vStatus["pleasedonthaveanamelikethis_plz_plz"] = false

		query, durls := generatePayloads(target, options, policy, pathReflection, params)
		pocs := performScanning(target, options, query, durls, rl, vStatus)

		scanObject.Results = pocs
		scanResult.PoCs = pocs
	}

	// Save scan results
	options.Scan[sid] = scanObject
	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)
	if !(options.Silence && options.MulticastMode) {
		printing.ScanSummary(scanResult, options)
	}
	if options.ReportBool {
		printing.DalLog("SYSTEM-M", "Report\n", options)
		if options.ReportFormat == "json" {
			jobject, err := json.MarshalIndent(scanResult, "", " ")
			if err == nil {
				fmt.Println(string(jobject))
			}
		} else {
			report.GenerateReport(scanResult, options)
		}
	}
	return scanResult, nil
}

// generatePayloads generates XSS payloads based on discovery results.
// getBlindCallbackURL determines the correct format for the blind callback URL.
// It assumes blindURL is not empty.
func getBlindCallbackURL(blindURL string) string {
	if strings.HasPrefix(blindURL, "https://") || strings.HasPrefix(blindURL, "http://") {
		return blindURL
	}
	return "//" + blindURL
}

func generatePayloads(target string, options model.Options, policy map[string]string, pathReflection map[int]string, params map[string]model.ParamResult) (map[*http.Request]map[string]string, []string) {
	query := make(map[*http.Request]map[string]string)
	var durls []string
	parsedURL, _ := url.Parse(target)

	printing.DalLog("SYSTEM", "Generating XSS payloads and performing optimization", options)

	// Handling JSON data if options.DataAsJSON is true
	if options.DataAsJSON && options.Data != "" {
		printing.DalLog("SYSTEM", "Processing data as JSON", options)
		var jsonData interface{}
		err := json.Unmarshal([]byte(options.Data), &jsonData)
		if err != nil {
			printing.DalLog("ERROR", "Failed to parse JSON data: "+err.Error(), options)
			// Potentially return or handle error appropriately
		} else {
			// Call the recursive function to generate payloads for JSON data
			// This function will be implemented in subsequent steps.
			// generateJSONPayloadsRecursive(target, jsonData, options, query, "")
			printing.DalLog("INFO", "JSON data parsed successfully. Payload generation for JSON is pending full implementation.", options)
			// For now, we will prevent further processing of URL/Form data if JSON is handled.
			// This return is temporary until JSON payload generation is complete.
			// TODO: Remove this return when generateJSONPayloadsRecursive is fully implemented.
			// return query, durls 
		}
		// If DataAsJSON is true, we assume the primary payload target is the JSON body.
		// We might still want to test path-based XSS, but parameter-based XSS in query/form
		// might be less relevant or could be handled separately if needed.
		// For now, let's assume if DataAsJSON, we skip the other payload generations for params.
		// Path-based XSS might still be relevant.
	}

	// Handling JSON data if options.DataAsJSON is true
	if options.DataAsJSON && options.Data != "" {
		printing.DalLog("SYSTEM", "Processing data as JSON", options)
		var originalJSONData interface{} // To store the initial parsed JSON for deep copying
		err := json.Unmarshal([]byte(options.Data), &originalJSONData)
		if err != nil {
			printing.DalLog("ERROR", "Failed to parse JSON data: "+err.Error(), options)
			// If JSON parsing fails, we might want to fall back to default behavior or stop.
			// For now, let's assume we can't proceed with JSON-specific logic if parsing fails.
		} else {
			printing.DalLog("INFO", "JSON data parsed successfully. Starting payload generation for JSON body.", options)
			generateJSONPayloadsRecursive(target, originalJSONData, options, query, "", originalJSONData)
			// If DataAsJSON is true, we assume the primary payload target is the JSON body.
			// We might still want to test path-based XSS.
			// Parameter-based XSS in query/form (Common Payloads and DOM XSS section) will be skipped by later checks.
		}
	}

	// Path-based XSS
	if !options.OnlyCustomPayload {
		for k, v := range pathReflection {
			if strings.Contains(v, "Injected:") {
				injectedPoint := strings.Split(v, "/")[1:]
				for _, ip := range injectedPoint {
					var arr []string
					if strings.Contains(ip, "inJS") {
						arr = optimization.SetPayloadValue(payload.GetInJsPayload(ip), options)
					}
					if strings.Contains(ip, "inHTML") {
						arr = optimization.SetPayloadValue(payload.GetHTMLPayload(ip), options)
					}
					if strings.Contains(ip, "inATTR") {
						arr = optimization.SetPayloadValue(payload.GetAttrPayload(ip), options)
					}
					for _, avv := range arr {
						var tempURL string
						if len(parsedURL.Path) == 0 {
							tempURL = target + "/" + avv
						} else {
							split := strings.Split(target, "/")
							split[k+3] = split[k+3] + avv
							tempURL = strings.Join(split, "/")
						}
						tq, tm := optimization.MakeRequestQuery(tempURL, "", "", ip, "toAppend", "NaN", options)
						tm["payload"] = avv
						query[tq] = tm
					}
				}
			}
		}
	}

	// Custom Payload
	if (options.SkipDiscovery || utils.IsAllowType(policy["Content-Type"])) && options.CustomPayloadFile != "" {
		ff, err := voltFile.ReadLinesOrLiteral(options.CustomPayloadFile)
		if err != nil {
			printing.DalLog("SYSTEM", "Failed to load custom XSS payload file", options)
		} else {
			for _, customPayload := range ff {
				if customPayload != "" {
					for k, v := range params {
						if optimization.CheckInspectionParam(options, k) {
							ptype := ""
							for _, av := range v.Chars {
								if strings.Contains(av, "PTYPE:") {
									ptype = GetPType(av)
								}
							}
							encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
							for _, encoder := range encoders {
								tq, tm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML"+ptype, "toAppend", encoder, options)
								query[tq] = tm
							}
						}
					}
				}
			}
			printing.DalLog("SYSTEM", "Added "+strconv.Itoa(len(ff))+" custom XSS payloads", options)
		}
	}

	// Common Payloads and DOM XSS
	// Skip this section if DataAsJSON is true and options.Data is not empty,
	// as we are focusing on JSON body payloads.
	if !(options.DataAsJSON && options.Data != "") && (options.SkipDiscovery || utils.IsAllowType(policy["Content-Type"])) && !options.OnlyCustomPayload {
		cu, _ := url.Parse(target)
		var cp, cpd url.Values
		var cpArr, cpdArr []string
		hashParam := false
		// This logic for cp and cpd needs to be careful if options.DataAsJSON is true.
		// If DataAsJSON is true, options.Data is JSON, not form data.
		if options.Data == "" || options.DataAsJSON { // Modified condition
			cp, _ = url.ParseQuery(cu.RawQuery)
			if len(cp) == 0 {
				cp, _ = url.ParseQuery(cu.Fragment)
				hashParam = true
			}
		} else { // This means options.Data is form data
			cp, _ = url.ParseQuery(cu.RawQuery)
			cpd, _ = url.ParseQuery(options.Data)
		}

		for v := range cp {
			if optimization.CheckInspectionParam(options, v) {
				cpArr = append(cpArr, v)
				arc := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
				for _, avv := range arc {
					encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
					for _, encoder := range encoders {
						tq, tm := optimization.MakeRequestQuery(target, v, avv, "inHTML-URL", "toAppend", encoder, options)
						query[tq] = tm
					}
				}
			}
		}

		for v := range cpd {
			if optimization.CheckInspectionParam(options, v) {
				cpdArr = append(cpdArr, v)
				arc := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
				for _, avv := range arc {
					encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
					for _, encoder := range encoders {
						tq, tm := optimization.MakeRequestQuery(target, v, avv, "inHTML-FORM", "toAppend", encoder, options)
						query[tq] = tm
					}
				}
			}
		}

		// DOM XSS Payloads
		if options.UseHeadless {
			var dlst []string
			if options.UseDeepDXSS {
				dlst = payload.GetDeepDOMXSPayload()
			} else {
				dlst = payload.GetDOMXSSPayload()
			}
			dpayloads := optimization.SetPayloadValue(dlst, options)
			for v := range cp {
				if optimization.CheckInspectionParam(options, v) && len(params[v].Chars) == 0 {
					for _, dpayload := range dpayloads {
						u, _ := url.Parse(target)
						dp, _ := url.ParseQuery(u.RawQuery)
						if hashParam {
							dp, _ = url.ParseQuery(u.Fragment)
							dp.Set(v, dpayload)
							u.Fragment, _ = url.QueryUnescape(dp.Encode())
						} else {
							dp.Set(v, dpayload)
							u.RawQuery = dp.Encode()
						}
						durls = append(durls, u.String())
					}
				}
			}
			for v := range cpd {
				if optimization.CheckInspectionParam(options, v) && len(params[v].Chars) == 0 {
					for _, dpayload := range dpayloads {
						u, _ := url.Parse(target)
						dp, _ := url.ParseQuery(u.RawQuery)
						if hashParam {
							dp, _ = url.ParseQuery(u.Fragment)
							dp.Set(v, dpayload)
							u.Fragment, _ = url.QueryUnescape(dp.Encode())
						} else {
							dp.Set(v, dpayload)
							u.RawQuery = dp.Encode()
						}
						durls = append(durls, u.String())
					}
				}
			}
		}

		// Parameter-based XSS
		// Skip this section if DataAsJSON is true and options.Data is not empty
		if !(options.DataAsJSON && options.Data != "") {
			for k, v := range params {
				if optimization.CheckInspectionParam(options, k) {
					ptype := ""
				chars := payload.GetSpecialChar()
				var badchars []string
				for _, av := range v.Chars {
					if utils.IndexOf(av, chars) == -1 {
						badchars = append(badchars, av)
					}
					if strings.Contains(av, "PTYPE:") {
						ptype = GetPType(av)
					}
					if strings.Contains(av, "Injected:") {
						injectedPoint := strings.Split(av, "/")[1:]
						injectedChars := params[k].Chars[:len(params[k].Chars)-1]
						for _, ip := range injectedPoint {
							var arr []string
							if strings.Contains(ip, "inJS") {
								checkInJS := false
								if strings.Contains(ip, "double") {
									for _, ic := range injectedChars {
										if strings.Contains(ic, "\"") {
											checkInJS = true
										}
									}
								}
								if strings.Contains(ip, "single") {
									for _, ic := range injectedChars {
										if strings.Contains(ic, "'") {
											checkInJS = true
										}
									}
								}
								if checkInJS {
									arr = optimization.SetPayloadValue(payload.GetInJsPayload(ip), options)
								} else {
									arr = optimization.SetPayloadValue(payload.GetInJsBreakScriptPayload(ip), options)
								}
							}
							if strings.Contains(ip, "inHTML") {
								arr = optimization.SetPayloadValue(payload.GetHTMLPayload(ip), options)
							}
							if strings.Contains(ip, "inATTR") {
								arr = optimization.SetPayloadValue(payload.GetAttrPayload(ip), options)
							}
							for _, avv := range arr {
								if optimization.Optimization(avv, badchars) {
									encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
									for _, encoder := range encoders {
										tq, tm := optimization.MakeRequestQuery(target, k, avv, ip+ptype, "toAppend", encoder, options)
										query[tq] = tm
									}
								}
							}
						}
					}
				}
					arc := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
					for _, avv := range arc {
						if !utils.ContainsFromArray(cpArr, k) && optimization.Optimization(avv, badchars) {
							encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
							for _, encoder := range encoders {
								tq, tm := optimization.MakeRequestQuery(target, k, avv, "inHTML"+ptype, "toAppend", encoder, options)
								query[tq] = tm
							}
						}
					}
				}
			}
		} // End of if !(options.DataAsJSON && options.Data != "") for Parameter-based XSS
	} else if !(options.DataAsJSON && options.Data != "") { // Added else if to avoid logging when JSON is processed
		printing.DalLog("SYSTEM", "Content-Type is '"+policy["Content-Type"]+"', only testing with customized payloads (custom/blind)", options)
	}

	// Blind Payload - This should still run regardless of DataAsJSON, as it can be in headers or other params
	if options.BlindURL != "" {
		bpayloads := payload.GetBlindPayload()
		bcallback := getBlindCallbackURL(options.BlindURL)
		for _, bpayload := range bpayloads {
			bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
			tq, tm := optimization.MakeHeaderQuery(target, "Referer", bp, options)
			tm["payload"] = "toBlind"
			query[tq] = tm
		}
		// If not DataAsJSON, also test blind payloads in parameters
		if !(options.DataAsJSON && options.Data != "") {
			for k, v := range params {
				if optimization.CheckInspectionParam(options, k) {
					ptype := ""
					for _, av := range v.Chars {
						if strings.Contains(av, "PTYPE:") {
							ptype = GetPType(av)
						}
					}
					for _, bpayload := range bpayloads {
						bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
						encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
						for _, encoder := range encoders {
							tq, tm := optimization.MakeRequestQuery(target, k, bp, "toBlind"+ptype, "toAppend", encoder, options)
							tm["payload"] = "toBlind"
							query[tq] = tm
						}
					}
				}
			}
		}
		printing.DalLog("SYSTEM", "Added blind XSS payloads with callback URL: "+options.BlindURL, options)
	}

	// Custom Blind XSS Payloads from file
	if options.CustomBlindXSSPayloadFile != "" {
		fileInfo, statErr := os.Stat(options.CustomBlindXSSPayloadFile)
		if os.IsNotExist(statErr) {
			printing.DalLog("SYSTEM", "Failed to load custom blind XSS payload file: "+options.CustomBlindXSSPayloadFile+" (file not found)", options)
		} else if statErr != nil {
			printing.DalLog("SYSTEM", "Failed to load custom blind XSS payload file: "+options.CustomBlindXSSPayloadFile+" ("+statErr.Error()+")", options)
		} else if fileInfo.IsDir() {
			printing.DalLog("SYSTEM", "Failed to load custom blind XSS payload file: "+options.CustomBlindXSSPayloadFile+" (path is a directory)", options)
		} else {
			// File exists and is not a directory, proceed to read it
			payloadLines, readErr := voltFile.ReadLinesOrLiteral(options.CustomBlindXSSPayloadFile)
			if readErr != nil {
				printing.DalLog("SYSTEM", "Failed to read custom blind XSS payload file: "+options.CustomBlindXSSPayloadFile+" ("+readErr.Error()+")", options)
			} else {
				var bcallback string
				if options.BlindURL != "" {
					bcallback = getBlindCallbackURL(options.BlindURL)
				}

				addedPayloadCount := 0
				for _, customPayload := range payloadLines {
					if customPayload != "" {
						addedPayloadCount++
						actualPayload := customPayload
						if options.BlindURL != "" { // Only replace if BlindURL is set
							actualPayload = strings.Replace(customPayload, "CALLBACKURL", bcallback, -1)
						}

						for k, v := range params {
							if optimization.CheckInspectionParam(options, k) {
								ptype := ""
								for _, av := range v.Chars {
									if strings.Contains(av, "PTYPE:") {
										ptype = GetPType(av)
									}
								}
								// Use only NaN encoder to avoid encoding issues with custom payloads
								tq, tm := optimization.MakeRequestQuery(target, k, actualPayload, "toBlind"+ptype, "toBlind", NaN, options)
								tm["payload"] = "toBlind"
								query[tq] = tm
							}
						}
					}
				}
				printing.DalLog("SYSTEM", "Added "+strconv.Itoa(addedPayloadCount)+" custom blind XSS payloads from file: "+options.CustomBlindXSSPayloadFile, options)
			}
		}
	}

	// Remote Payloads
	if options.RemotePayloads != "" {
		rp := strings.Split(options.RemotePayloads, ",")
		for _, endpoint := range rp {
			var payloads []string
			var line, size string
			if endpoint == "portswigger" {
				payloads, line, size = payload.GetPortswiggerPayload()
			}
			if endpoint == "payloadbox" {
				payloads, line, size = payload.GetPayloadBoxPayload()
			}
			if line != "" {
				printing.DalLog("INFO", "Successfully loaded '"+endpoint+"' payloads ["+line+" lines / "+size+"]", options)
				for _, remotePayload := range payloads {
					if remotePayload != "" {
						for k, v := range params {
							if optimization.CheckInspectionParam(options, k) {
								ptype := ""
								for _, av := range v.Chars {
									if strings.Contains(av, "PTYPE:") {
										ptype = GetPType(av)
									}
								}
								encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, remotePayload, "inHTML"+ptype, "toAppend", encoder, options)
									query[tq] = tm
								}
							}
						}
					}
				}
			} else {
				printing.DalLog("SYSTEM", "Failed to load remote payloads from "+endpoint, options)
			}
		}
	}

	return query, durls
}

// deepCopyJSON creates a deep copy of a JSON structure by marshalling and unmarshalling.
func deepCopyJSON(data interface{}) (interface{}, error) {
	if data == nil {
		return nil, nil
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal for deep copy: %w", err)
	}
	var copy interface{}
	err = json.Unmarshal(bytes, &copy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal for deep copy: %w", err)
	}
	return copy, nil
}

// setJSONValueByPath modifies a JSON structure by setting a value at a given path.
// path is a dot-separated string for objects and [index] for arrays.
// e.g., "user.details.email" or "user.friends[0].name"
// IMPORTANT: This function modifies the input `jsonObj` directly if it's a map or slice.
// It's intended to be used on a deep copy of the original JSON data.
func setJSONValueByPath(jsonObj interface{}, path string, valueToSet string) error {
	// Simplified path splitting, assuming dot notation for objects and `[index]` for arrays.
	// Example paths: "key", "object.key", "array[0]", "object.array[0].key"
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	})

	current := jsonObj
	for i, part := range parts {
		if part == "" { // Skip empty parts that can result from splitting e.g. array[0]
			continue
		}
		isLastPart := (i == len(parts)-1)

		// Attempt to parse part as an array index first
		index, err := strconv.Atoi(part)
		if err == nil { // It's an array index
			arr, ok := current.([]interface{})
			if !ok {
				return fmt.Errorf("path '%s' expected array at segment '%s', but got %T", path, part, current)
			}
			if index < 0 || index >= len(arr) {
				return fmt.Errorf("array index %d out of bounds for path '%s'", index, path)
			}
			if isLastPart {
				arr[index] = valueToSet
				return nil
			}
			current = arr[index]
		} else { // It's an object key
			objMap, ok := current.(map[string]interface{})
			if !ok {
				// This case can happen if an array index was expected but not found, and part is not a number
				// Or if the structure is not as expected.
				return fmt.Errorf("path '%s' expected object for key '%s', but got %T", path, part, current)
			}
			if isLastPart {
				objMap[part] = valueToSet
				return nil
			}
			next, exists := objMap[part]
			if !exists {
				return fmt.Errorf("key '%s' not found in path '%s'", part, path)
			}
			current = next
		}
	}
	return fmt.Errorf("path '%s' did not lead to a settable location, current value: %v", path, current)
}

// generateJSONPayloadsRecursive traverses the JSON data and injects payloads into string values.
func generateJSONPayloadsRecursive(originalTarget string, currentJsonData interface{}, options model.Options, query map[*http.Request]map[string]string, currentPath string, originalJSONDataForCopy interface{}) {
	switch v := currentJsonData.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := key
			if currentPath != "" {
				newPath = currentPath + "." + key
			}
			generateJSONPayloadsRecursive(originalTarget, value, options, query, newPath, originalJSONDataForCopy)
		}
	case []interface{}:
		for i, item := range v {
			var newPath string
			if currentPath == "" { // Root is an array
				newPath = fmt.Sprintf("[%d]", i)
			} else if strings.HasSuffix(currentPath, "]") { // currentPath is already an array element, e.g. array[0] for a nested array
                // This case needs careful handling if we want paths like array[0][1]
                // For now, let's assume simple nesting: object.array[index] or array[index].object
                // A more robust path builder might be needed for complex nested arrays within arrays.
                // This simplification means path might look like "somearray[0].key" or "somearray[0]"
                // If we are inside an array element that is itself an array, the path concatenation needs to be smarter.
                // Let's adjust to: currentPath + fmt.Sprintf("[%d]", i) -> e.g. base[0][1]
                // No, if currentPath is "arr[0]", next is "arr[0][1]" - this is not standard dot notation.
                // Let's use currentPath + "." + strconv.Itoa(i) if the parent was an object,
                // and currentPath + fmt.Sprintf("[%d]", i) if the parent was an array.
                // The current path construction for maps (currentPath + "." + key) and arrays (currentPath + newPathSegment) needs to be consistent.
                // Simplified: if currentPath is "obj.arr", new path for element is "obj.arr[0]". If currentPath is "arr", new path is "arr[0]".
                // The parts extraction in setJSONValueByPath handles "key" and "index" separately.
				newPath = fmt.Sprintf("%s[%d]", currentPath, i) // This might lead to "key[0][1]" which is fine
			} else { // currentPath is an object key, and this is an array field
				newPath = fmt.Sprintf("%s[%d]", currentPath, i)
			}
			generateJSONPayloadsRecursive(originalTarget, item, options, query, newPath, originalJSONDataForCopy)
		}
	case string:
		if currentPath == "" {
			// This case should ideally not happen if the root JSON is an object or array.
			// If options.Data is just a string, and DataAsJSON is true, it's ambiguous.
			// For now, we only inject into strings that are part of an object or array.
			printing.DalLog("DEBUG", "Skipping payload injection for root string data.", options)
			return
		}

		payloadsToTest := optimization.SetPayloadValue(payload.GetCommonPayload(), options)

		for _, xssPayload := range payloadsToTest {
			copiedData, err := deepCopyJSON(originalJSONDataForCopy)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to deep copy JSON for path '%s': %v", currentPath, err), options)
				continue
			}

			err = setJSONValueByPath(copiedData, currentPath, xssPayload)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to set JSON value at path '%s' with payload '%s': %v", currentPath, xssPayload, err), options)
				continue
			}
			
			marshalledModifiedJSON, err := json.Marshal(copiedData)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to marshal modified JSON for path '%s': %v", currentPath, err), options)
				continue
			}

			// Using "jsonBody" as replaceType. This will need to be handled in MakeRequestQuery.
			// paramName (second arg to MakeRequestQuery) is the JSON path.
			// value (third arg) is the entire marshalled JSON string.
			tq, tm := optimization.MakeRequestQuery(originalTarget, currentPath, string(marshalledModifiedJSON), "inJSON", "jsonBody", NaN, options)
			if tq != nil {
				tm["payload"] = xssPayload      // Store the raw XSS payload for context
				tm["json_path"] = currentPath   // Store the JSON path for context
				tm["original_body"] = options.Data // Store original body for context if needed
				query[tq] = tm
				if options.Debug {
					printing.DalLog("DEBUG", fmt.Sprintf("Generated JSON payload for path '%s', XSS payload: '%s', Full JSON: %s", currentPath, xssPayload, string(marshalledModifiedJSON)), options)
				}
			} else {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to create request query for JSON payload at path '%s'", currentPath), options)
			}
		}
	default:
		// printing.DalLog("DEBUG", fmt.Sprintf("Ignoring type %T at path '%s'", v, currentPath), options)
	}
}

// updateSpinner updates the spinner message during scanning.
func deepCopyJSON(data interface{}) (interface{}, error) {
	if data == nil {
		return nil, nil
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal for deep copy: %w", err)
	}
	var copy interface{}
	err = json.Unmarshal(bytes, &copy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal for deep copy: %w", err)
	}
	return copy, nil
}

// setJSONValueByPath modifies a JSON structure by setting a value at a given path.
// path is a dot-separated string for objects and [index] for arrays.
// e.g., "user.details.email" or "user.friends[0].name"
func setJSONValueByPath(jsonObj interface{}, path string, valueToSet string) (interface{}, error) {
	parts := strings.Split(path, ".") // Simple split, doesn't handle array indexing yet
	current := jsonObj

	for i, part := range parts {
		// Handle array indexing if part contains [index]
		if strings.Contains(part, "[") && strings.HasSuffix(part, "]") {
			arrayPart := strings.SplitN(part, "[", 2)
			arrayName := arrayPart[0]
			indexStr := strings.TrimSuffix(arrayPart[1], "]")
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid array index in path '%s': %s", path, indexStr)
			}

			if arrayName != "" { // Accessing an array field in an object
				objMap, ok := current.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("path '%s' expected object for array field '%s', got %T", path, arrayName, current)
				}
				arrInterface, ok := objMap[arrayName]
				if !ok {
					return nil, fmt.Errorf("array field '%s' not found in path '%s'", arrayName, path)
				}
				arr, ok := arrInterface.([]interface{})
				if !ok {
					return nil, fmt.Errorf("field '%s' in path '%s' is not an array", arrayName, path)
				}
				if index < 0 || index >= len(arr) {
					return nil, fmt.Errorf("array index %d out of bounds for '%s' in path '%s'", index, arrayName, path)
				}
				current = arr[index] // Move current to the element within the array
			} else { // current itself is an array
				arr, ok := current.([]interface{})
				if !ok {
					return nil, fmt.Errorf("path part '%s' implies array, but current is %T", part, current)
				}
				if index < 0 || index >= len(arr) {
					return nil, fmt.Errorf("array index %d out of bounds for path '%s'", index, path)
				}
				current = arr[index]
			}
		} else { // Object field
			objMap, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("path '%s' expected object for key '%s', got %T", path, part, current)
			}
			if i == len(parts)-1 { // Last part, set the value
				objMap[part] = valueToSet
			} else {
				var found bool
				current, found = objMap[part]
				if !found {
					// Or create intermediate maps: objMap[part] = make(map[string]interface{})
					// For now, let's error if path doesn't exist.
					return nil, fmt.Errorf("key '%s' not found in path '%s'", part, path)
				}
			}
		}
	}
	// This function currently modifies in place due to map/slice reference semantics.
	// The deepCopy should happen before calling this if non-destructive modification is needed.
	// For the XSS use case, we will deep copy the *original* JSON first, then call this.
	return jsonObj, nil // Return the modified object
}

// generateJSONPayloadsRecursive traverses the JSON data and injects payloads into string values.
func generateJSONPayloadsRecursive(originalTarget string, currentJsonData interface{}, options model.Options, query map[*http.Request]map[string]string, currentPath string, originalJSONData interface{}) {
	switch v := currentJsonData.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := key
			if currentPath != "" {
				newPath = currentPath + "." + key
			}
			generateJSONPayloadsRecursive(originalTarget, value, options, query, newPath, originalJSONData)
		}
	case []interface{}:
		for i, item := range v {
			newPath := fmt.Sprintf("[%d]", i)
			if currentPath != "" {
				newPath = currentPath + newPath // e.g. obj.array[0] or array[0] if root
			}
			generateJSONPayloadsRecursive(originalTarget, item, options, query, newPath, originalJSONData)
		}
	case string:
		// This is where payload injection happens.
		// For now, just log that we found a string.
		// printing.DalLog("DEBUG", fmt.Sprintf("Found string at path '%s': %s", currentPath, v), options)
		
		// Iterate through common XSS payloads
		payloadsToTest := optimization.SetPayloadValue(payload.GetCommonPayload(), options) // Or other relevant payload sets

		for _, xssPayload := range payloadsToTest {
			// 1. Create a deep copy of the *original* top-level JSON structure.
			copiedData, err := deepCopyJSON(originalJSONData)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to deep copy JSON for path %s: %v", currentPath, err), options)
				continue
			}

			// 2. Modify this deep copy by placing the XSS payload into the current string's position.
			modifiedJSON, err := setJSONValueByPath(copiedData, currentPath, xssPayload)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to set JSON value at path %s: %v", currentPath, err), options)
				continue
			}
			
			// 3. Marshal the modified deep copy back into a JSON string.
			marshalledModifiedJSON, err := json.Marshal(modifiedJSON)
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to marshal modified JSON for path %s: %v", currentPath, err), options)
				continue
			}

			// 4. Create the request and metadata.
			// Using "toBody" as a placeholder for replaceType, this will need handling in MakeRequestQuery or request sending.
			// paramName is currentPath, value is the marshalledModifiedJSONString.
			// injectionType is "inJSON". encoder is NaN.
			tq, tm := optimization.MakeRequestQuery(originalTarget, currentPath, string(marshalledModifiedJSON), "inJSON", "toBody", NaN, options)
			if tq != nil {
				tm["payload"] = xssPayload // Store the raw XSS payload for context
				tm["json_path"] = currentPath // Store the JSON path for context
				query[tq] = tm
				printing.DalLog("DEBUG", fmt.Sprintf("Generated JSON payload for path '%s', value: %s", currentPath, xssPayload), options)
			} else {
				printing.DalLog("ERROR", fmt.Sprintf("Failed to create request query for JSON payload at path '%s'", currentPath), options)
			}
		}
	// Other types (numbers, booleans, nil) are ignored for direct payload injection.
	// They are preserved by the deepCopyJSON and setJSONValueByPath logic.
	default:
		// printing.DalLog("DEBUG", fmt.Sprintf("Ignoring type %T at path '%s'", v, currentPath), options)
	}
}


// updateSpinner updates the spinner message during scanning.
func updateSpinner(options model.Options, queryCount, totalQueries int, param string, status bool) {
	if !(options.Silence || options.NoSpinner) {
		s.Lock()
		var msg string
		if status {
			if options.UseHeadless {
				msg = "Passing \"" + param + "\" param queries and waiting headless"
			} else {
				msg = "Passing \"" + param + "\" param queries"
			}
		} else {
			if options.UseHeadless {
				msg = "Testing \"" + param + "\" param and waiting headless"
			} else {
				msg = "Testing \"" + param + "\" param"
			}
		}
		percent := fmt.Sprintf("%0.2f%%", (float64(queryCount)/float64(totalQueries))*100)
		if options.NowURL == 0 {
			s.Suffix = "  [" + strconv.Itoa(queryCount) + "/" + strconv.Itoa(totalQueries) + " Queries][" + percent + "] " + msg
		} else if !options.Silence {
			percent2 := fmt.Sprintf("%0.2f%%", (float64(options.NowURL) / float64(options.AllURLS) * 100))
			s.Suffix = "  [" + strconv.Itoa(queryCount) + "/" + strconv.Itoa(totalQueries) + " Queries][" + percent + "][" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent2 + "] " + msg
		}
		s.Unlock()
	}
}

// initializeSpinner initializes the spinner with the given options.
func initializeSpinner(options model.Options) {
	time.Sleep(1 * time.Second) // Waiting log
	s.Prefix = " "
	s.Suffix = ""
	if !options.NoColor {
		s.Color("red", "bold")
	}
	if options.SpinnerObject != nil {
		s = options.SpinnerObject
	} else {
		options.SpinnerObject = s
	}
	s.Start()
}

// logStartScan logs the start of the scan.
func logStartScan(target string, options model.Options, sid string) {
	printing.DalLog("SYSTEM", "Starting scan", options)
	if options.AllURLS > 0 {
		snow, _ := strconv.Atoi(sid)
		percent := fmt.Sprintf("%0.2f%%", float64(snow)/float64(options.AllURLS)*100)
		printing.DalLog("SYSTEM-M", "Starting scan [SID:"+sid+"]["+sid+"/"+strconv.Itoa(options.AllURLS)+"]["+percent+"%] / URL: "+target, options)
	} else {
		printing.DalLog("SYSTEM-M", "Starting scan [SID:"+sid+"] / URL: "+target, options)
	}
}

// createHTTPClient creates an HTTP client with the given options.
func createHTTPClient(options model.Options) *http.Client {
	transport := getTransport(options)
	t := options.Timeout
	client := &http.Client{
		Timeout:   time.Duration(t) * time.Second,
		Transport: transport,
	}

	if !options.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// shouldIgnoreReturn checks if the response status code should be ignored.
func shouldIgnoreReturn(statusCode int, ignoreReturn string) bool {
	rcode := strings.Split(ignoreReturn, ",")
	tcode := strconv.Itoa(statusCode)
	for _, v := range rcode {
		if tcode == v {
			return true
		}
	}
	return false
}

// logPolicyAndPathReflection logs the policy and path reflection information.
func logPolicyAndPathReflection(policy map[string]string, options model.Options, parsedURL *url.URL) {
	for k, v := range policy {
		if len(v) != 0 {
			if k == "BypassCSP" {
				printing.DalLog("WEAK", k+": "+v, options)
			} else {
				printing.DalLog("INFO", k+" is "+v, options)
			}
		}
	}
	for k, v := range options.PathReflection {
		if len(parsedURL.Path) == 0 {
			str := options.AuroraObject.Yellow("dalfoxpathtest").String()
			printing.DalLog("INFO", "Reflected PATH '/"+str+"' => "+v+"]", options)
		} else {
			split := strings.Split(parsedURL.Path, "/")
			if len(split) > k+1 {
				split[k+1] = options.AuroraObject.Yellow("dalfoxpathtest").String()
				tempURL := strings.Join(split, "/")
				printing.DalLog("INFO", "Reflected PATH '"+tempURL+"' => "+v+"]", options)
			}
		}
	}
}
