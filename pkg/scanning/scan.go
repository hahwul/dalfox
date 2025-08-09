package scanning

import (
	"bytes"
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

// JSONInjector handles JSON payload injection
type JSONInjector struct {
	OriginalJSON map[string]interface{}
	Payload      string
}

// InjectIntoJSON recursively injects payload into JSON structure
func (ji *JSONInjector) InjectIntoJSON(data interface{}, path string) []map[string]interface{} {
	var results []map[string]interface{}

	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			currentPath := path
			if currentPath != "" {
				currentPath += "."
			}
			currentPath += key

			// Create a copy and inject payload
			modified := ji.deepCopy(data)
			if modifiedMap, ok := modified.(map[string]interface{}); ok {
				modifiedMap[key] = ji.Payload
				results = append(results, map[string]interface{}{
					"json": modified,
					"path": currentPath,
					"key":  key,
				})
			}

			// Recursively process nested structures
			nestedResults := ji.InjectIntoJSON(value, currentPath)
			results = append(results, nestedResults...)
		}

	case []interface{}:
		for i, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, i)

			// Create a copy and inject payload at array index
			modified := ji.deepCopy(data)
			if modifiedArray, ok := modified.([]interface{}); ok && i < len(modifiedArray) {
				modifiedArray[i] = ji.Payload
				results = append(results, map[string]interface{}{
					"json": modified,
					"path": currentPath,
					"key":  fmt.Sprintf("[%d]", i),
				})
			}

			// Recursively process array items
			nestedResults := ji.InjectIntoJSON(item, currentPath)
			results = append(results, nestedResults...)
		}
	}

	return results
}

// deepCopy creates a deep copy of the interface{}
func (ji *JSONInjector) deepCopy(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		copy := make(map[string]interface{})
		for key, value := range v {
			copy[key] = ji.deepCopy(value)
		}
		return copy

	case []interface{}:
		copy := make([]interface{}, len(v))
		for i, item := range v {
			copy[i] = ji.deepCopy(item)
		}
		return copy

	default:
		return v
	}
}

// ParseJSONBody parses JSON body and returns injection points
func ParseJSONBody(body string, payload string) ([]map[string]interface{}, error) {
	var jsonData interface{}
	err := json.Unmarshal([]byte(body), &jsonData)
	if err != nil {
		return nil, err
	}

	injector := &JSONInjector{
		Payload: payload,
	}

	return injector.InjectIntoJSON(jsonData, ""), nil
}

// CreateJSONRequest creates HTTP request with modified JSON body
func CreateJSONRequest(originalReq *http.Request, modifiedJSON interface{}) (*http.Request, error) {
	jsonBytes, err := json.Marshal(modifiedJSON)
	if err != nil {
		return nil, err
	}

	// Create new request with modified JSON body
	newReq, err := http.NewRequest(originalReq.Method, originalReq.URL.String(), bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}

	// Copy headers
	for key, values := range originalReq.Header {
		for _, value := range values {
			newReq.Header.Add(key, value)
		}
	}

	// Set content type and length
	newReq.Header.Set("Content-Type", "application/json")
	newReq.Header.Set("Content-Length", strconv.Itoa(len(jsonBytes)))

	return newReq, nil
}

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
		} else if options.ReportFormat == "markdown" || options.ReportFormat == "md" {
			markdownReport := report.GenerateMarkdownReport(scanResult, options)
			fmt.Println(markdownReport)
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

	// Magic Character Tests (Issue #695)
	if options.MagicCharTest && !options.OnlyCustomPayload {
		printing.DalLog("SYSTEM", "Performing magic character tests for manual XSS analysis", options)
		for k, v := range params {
			if optimization.CheckInspectionParam(options, k) {
				// Detect context if ContextAware is enabled
				context := "html" // default
				if options.ContextAware {
					// Use the reflected code to detect context
					context = utils.DetectContext(v.ReflectedCode, k, "test")
					printing.DalLog("INFO", "Detected context for "+k+": "+context, options)
				}

				// Generate magic character payloads
				magicChars := []string{
					utils.GenerateMagicCharacter(context),
					utils.GenerateMagicString(context, 3),
					utils.GenerateTestPayload(context),
				}

				for _, magicPayload := range magicChars {
					encoders := []string{NaN, urlEncode, htmlEncode}
					for _, encoder := range encoders {
						tq, tm := optimization.MakeRequestQuery(target, k, magicPayload, "inHTML-MAGIC", "toAppend", encoder, options)
						tm["magic_test"] = "true"
						tm["context"] = context
						query[tq] = tm
					}
				}
			}
		}
		printing.DalLog("SYSTEM", "Added magic character test payloads", options)
	}

	// Common Payloads and DOM XSS
	if (options.SkipDiscovery || utils.IsAllowType(policy["Content-Type"])) && !options.OnlyCustomPayload {
		cu, _ := url.Parse(target)
		var cp, cpd url.Values
		var cpArr, cpdArr []string
		hashParam := false
		if options.Data == "" {
			cp, _ = url.ParseQuery(cu.RawQuery)
			if len(cp) == 0 {
				cp, _ = url.ParseQuery(cu.Fragment)
				hashParam = true
			}
		} else {
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
										if ptype == "-JSON" {
											tq, tm := optimization.MakeJSONRequestQuery(target, k, avv, ip+ptype, "toAppend", encoder, options)
											query[tq] = tm
										} else {
											tq, tm := optimization.MakeRequestQuery(target, k, avv, ip+ptype, "toAppend", encoder, options)
											query[tq] = tm
										}
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
							if ptype == "-JSON" {
								tq, tm := optimization.MakeJSONRequestQuery(target, k, avv, "inHTML"+ptype, "toAppend", encoder, options)
								query[tq] = tm
							} else {
								tq, tm := optimization.MakeRequestQuery(target, k, avv, "inHTML"+ptype, "toAppend", encoder, options)
								query[tq] = tm
							}
						}
					}
				}
			}
		}
	} else {
		printing.DalLog("SYSTEM", "Content-Type is '"+policy["Content-Type"]+"', only testing with customized payloads (custom/blind)", options)
	}

	// Blind Payload
	if options.BlindURL != "" {
		bpayloads := payload.GetBlindPayload()
		bcallback := getBlindCallbackURL(options.BlindURL)
		for _, bpayload := range bpayloads {
			bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
			tq, tm := optimization.MakeHeaderQuery(target, "Referer", bp, options)
			tm["payload"] = "toBlind"
			query[tq] = tm
		}
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
						if ptype == "-JSON" {
							tq, tm := optimization.MakeJSONRequestQuery(target, k, bp, "toBlind"+ptype, "toAppend", encoder, options)
							tm["payload"] = "toBlind"
							query[tq] = tm
						} else {
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
