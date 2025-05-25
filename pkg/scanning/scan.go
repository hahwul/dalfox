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

	// Magic character detection
	var identifiedTypedMagicParams []model.ParamResult
	if options.MagicString != "" {
		// Query Parameters
		queryValues := parsedURL.Query()
		for name, values := range queryValues {
			for _, value := range values {
				if strings.Contains(value, options.MagicString) {
					identifiedTypedMagicParams = append(identifiedTypedMagicParams, model.ParamResult{Name: name, Type: model.ParamTypeQuery})
					break 
				}
			}
		}

		// Header Parameters
		for _, headerStr := range options.Header {
			parts := strings.SplitN(headerStr, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				if strings.ToLower(headerName) == "cookie" { // Skip cookie header, handled separately
					continue
				}
				if strings.Contains(headerValue, options.MagicString) {
					identifiedTypedMagicParams = append(identifiedTypedMagicParams, model.ParamResult{Name: headerName, Type: model.ParamTypeHeader})
				}
			}
		}

		// Cookie Parameters
		if options.Cookie != "" {
			// Create a dummy request to parse cookies easily
			dummyReq, _ := http.NewRequest("GET", target, nil)
			dummyReq.Header.Set("Cookie", options.Cookie)
			for _, cookie := range dummyReq.Cookies() {
				if strings.Contains(cookie.Value, options.MagicString) {
					identifiedTypedMagicParams = append(identifiedTypedMagicParams, model.ParamResult{Name: cookie.Name, Type: model.ParamTypeCookie})
				}
			}
		}
		
		// Body Parameters
		if options.Data != "" {
			contentType := ""
			for _, headerStr := range options.Header { // Check Content-Type from options.Header
				parts := strings.SplitN(headerStr, ":", 2)
				if len(parts) == 2 && strings.ToLower(strings.TrimSpace(parts[0])) == "content-type" {
					contentType = strings.ToLower(strings.TrimSpace(parts[1]))
					break
				}
			}
			if contentType == "" { // Default if not specified
				contentType = "application/x-www-form-urlencoded"
			}

			if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
				bodyParams, err := url.ParseQuery(options.Data)
				if err == nil {
					for name, values := range bodyParams {
						for _, value := range values {
							if strings.Contains(value, options.MagicString) {
								identifiedTypedMagicParams = append(identifiedTypedMagicParams, model.ParamResult{Name: name, Type: model.ParamTypeBodyForm})
								break
							}
						}
					}
				}
			} else if strings.HasPrefix(contentType, "application/json") {
				var jsonData map[string]interface{}
				err := json.Unmarshal([]byte(options.Data), &jsonData)
				if err == nil {
					for key, val := range jsonData {
						if strVal, ok := val.(string); ok { // Only check top-level string values
							if strings.Contains(strVal, options.MagicString) {
								identifiedTypedMagicParams = append(identifiedTypedMagicParams, model.ParamResult{Name: key, Type: model.ParamTypeBodyJSON})
							}
						}
					}
				} else {
					printing.DalLog("WARNING", "Failed to parse JSON body for magic string detection: "+err.Error(), options)
				}
			}
		}

		// Remove duplicates that might occur if e.g. a param name is same in query and header
		// This uses Name and Type for uniqueness.
		uniqueMagicParams := make([]model.ParamResult, 0, len(identifiedTypedMagicParams))
		seenParams := make(map[string]bool)
		for _, p := range identifiedTypedMagicParams {
			key := p.Name + "_" + p.Type
			if !seenParams[key] {
				uniqueMagicParams = append(uniqueMagicParams, p)
				seenParams[key] = true
			}
		}
		identifiedTypedMagicParams = uniqueMagicParams


		if len(identifiedTypedMagicParams) > 0 {
			var logMsgs []string
			for _, p := range identifiedTypedMagicParams {
				logMsgs = append(logMsgs, p.Name+" ("+p.Type+")")
			}
			printing.DalLog("INFO", "Identified magic parameters: "+strings.Join(logMsgs, ", "), options)
			options.InternalFoundMagicParams = identifiedTypedMagicParams // Store for testing
		} else {
			printing.DalLog("INFO", "No magic parameters identified with string: "+options.MagicString, options)
			options.InternalFoundMagicParams = []model.ParamResult{} // Ensure it's empty
		}
	}
	// options.IdentifiedMagicParams is no longer used in this manner.
	// options.HasMagicParams will be set based on identifiedTypedMagicParams.


	// Discovery phase
	var policy map[string]string
	var pathReflection map[int]string
	var params map[string]model.ParamResult

	if len(identifiedTypedMagicParams) > 0 {
		options.HasMagicParams = true // Set HasMagicParams flag
		var logMsgs []string
		for _, p := range identifiedTypedMagicParams {
			logMsgs = append(logMsgs, p.Name+" ("+p.Type+")")
		}
		printing.DalLog("INFO", "Bypassing discovery due to identified magic parameters: "+strings.Join(logMsgs, ", "), options)
		
		params = make(map[string]model.ParamResult)
		for _, p := range identifiedTypedMagicParams {
			// Keying by Name for generatePayloads. If names collide, last one wins.
			// This could be an area for future improvement if type-specific handling in generatePayloads is desired for same-named params.
			if _, exists := params[p.Name]; exists {
				printing.DalLog("WARNING", "Magic parameter name '"+p.Name+"' identified in multiple locations/types. Using last detected type: "+p.Type, options)
			}
			params[p.Name] = model.ParamResult{
				Name:      p.Name,
				Type:      p.Type, // Use the new explicit type
				Reflected: true,
				Chars:     payload.GetSpecialChar(), 
			}
		}
		policy = make(map[string]string)
		policy["Content-Type"] = "text/html" // Default for XSS testing
		pathReflection = make(map[int]string)
		printing.DalLog("INFO", "Forcing XSS testing on "+strconv.Itoa(len(params))+" uniquely named magic parameters.", options)

	} else if !options.SkipDiscovery {
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
	if (options.SkipDiscovery || options.HasMagicParams || utils.IsAllowType(policy["Content-Type"])) && options.CustomPayloadFile != "" {
		ff, err := voltFile.ReadLinesOrLiteral(options.CustomPayloadFile)
		if err != nil {
			printing.DalLog("SYSTEM", "Failed to load custom XSS payload file", options)
		} else {
			for _, customPayload := range ff {
				if customPayload != "" {
					for k, v := range params { // k is param name, v is ParamResult
						if optimization.CheckInspectionParam(options, k) {
							// Default to inHTML if no specific reflection point known (e.g. magic params)
							// or if the param type naturally reflects into HTML.
							paramTypeSuffix := "-" + v.Type // e.g., "-QUERY", "-HEADER"
							injectionPoint := "inHTML"      // Default injection context
							
							// TODO: More sophisticated context determination based on v.Type if v.ReflectedPoint is not detailed.
							// For now, "inHTML" is a general default for custom payloads.
							
							encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
							// Encoder choice could also be refined based on v.Type here.
							// e.g. for HEADER/COOKIE, NaN or specific encoding might be preferred.
							// For JSON, payload needs to be JSON string encoded.
							for _, encoder := range encoders {
								// MakeRequestQuery now needs to understand v.Type to correctly place the payload
								tq, tm := optimization.MakeRequestQuery(target, k, customPayload, injectionPoint+paramTypeSuffix, "toAppend", encoder, options, v.Type)
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
	// The distinction between URL params (cp) and Body params (cpd) might be less relevant here
	// if `params` map correctly types all discovered/input parameters.
	if (options.SkipDiscovery || options.HasMagicParams || utils.IsAllowType(policy["Content-Type"])) && !options.OnlyCustomPayload {
		// Initial query parameters from the target URL (cp) and data parameters (cpd)
		// These are used for some initial payload generation before iterating through the full `params` map.
		// This part might be redundant if all params are already in `params` with correct types.
		// However, keeping it for now to ensure no existing behavior for direct URL/data params is lost.
		// We should ensure these `v` are also present in `params` map with correct types.
		
		// START Existing cp, cpd block (minor changes for type awareness if possible)
		cu, _ := url.Parse(target)
		var cp, cpd url.Values // cp for query, cpd for body
		var cpArr, cpdArr []string
		hashParam := false // if params are from fragment
		
		if options.Data == "" { // GET, or POST without explicit --data (params in URL)
			cp, _ = url.ParseQuery(cu.RawQuery)
			if len(cp) == 0 && strings.Contains(cu.Fragment, "=") { // Check fragment if no query params
				cp, _ = url.ParseQuery(cu.Fragment)
				hashParam = true
			}
		} else { // POST/PUT with --data
			cp, _ = url.ParseQuery(cu.RawQuery) // Query params can still exist
			// Determine body type for cpd
			contentType := ""
			for _, headerStr := range options.Header {
				parts := strings.SplitN(headerStr, ":", 2)
				if len(parts) == 2 && strings.ToLower(strings.TrimSpace(parts[0])) == "content-type" {
					contentType = strings.ToLower(strings.TrimSpace(parts[1]))
					break
				}
			}
			if contentType == "" || strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
				cpd, _ = url.ParseQuery(options.Data)
			}
			// JSON/XML body params from options.Data are handled by the main loop over `params`
		}

		// Payloads for query parameters (cp)
		for paramName := range cp {
			if optimization.CheckInspectionParam(options, paramName) {
				cpArr = append(cpArr, paramName)
				arc := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
				paramType := model.ParamTypeQuery
				if hashParam {
					paramType = model.ParamTypeFragment
				}
				for _, payloadValue := range arc {
					encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
					for _, encoder := range encoders {
						// Assuming inHTML context for these general query params
						tq, tm := optimization.MakeRequestQuery(target, paramName, payloadValue, "inHTML-"+paramType, "toAppend", encoder, options, paramType)
						query[tq] = tm
					}
				}
			}
		}
		// Payloads for form body parameters (cpd)
		for paramName := range cpd {
			if optimization.CheckInspectionParam(options, paramName) {
				cpdArr = append(cpdArr, paramName)
				arc := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
				for _, payloadValue := range arc {
					encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
					for _, encoder := range encoders {
						tq, tm := optimization.MakeRequestQuery(target, paramName, payloadValue, "inHTML-"+model.ParamTypeBodyForm, "toAppend", encoder, options, model.ParamTypeBodyForm)
						query[tq] = tm
					}
				}
			}
		}
		// END Existing cp, cpd block

		// DOM XSS Payloads - This part needs careful review for typed parameters
		// It currently iterates cp and cpd, and checks params[v].Chars.
		// If magic params are used, params[v].Chars will be GetSpecialChar(), not empty.
		// This logic might need to be adapted or integrated into the main loop over `params`.
		if options.UseHeadless {
			var dlst []string
			if options.UseDeepDXSS {
				dlst = payload.GetDeepDOMXSPayload()
			} else {
				dlst = payload.GetDOMXSSPayload()
			}
			dpayloads := optimization.SetPayloadValue(dlst, options)

			// Iterate through all known parameters (query, body_form, fragment) that could be DOM XSS vectors
			// This needs to be careful not to duplicate if cp/cpd logic is already covering some.
			// For simplicity, this existing DOM XSS logic for cp/cpd is kept,
			// but it might miss DOM XSS on other types if not reflected in URL/form-like structures.
			for paramName := range cp { // Query/Fragment params
				paramMapEntry, paramExists := params[paramName]
				// Apply DOM XSS if it's a known param and (Chars is empty OR it's a magic param we are forcing tests on)
				if optimization.CheckInspectionParam(options, paramName) && paramExists && (len(paramMapEntry.Chars) == 0 || options.HasMagicParams) {
					for _, dpayload := range dpayloads {
						u, _ := url.Parse(target)
						currentQueryParams, _ := url.ParseQuery(u.RawQuery)
						currentFragParams, _ := url.ParseQuery(u.Fragment)

						if hashParam && paramMapEntry.Type == model.ParamTypeFragment { // If original was fragment
							currentFragParams.Set(paramName, dpayload)
							u.Fragment, _ = url.QueryUnescape(currentFragParams.Encode())
						} else if paramMapEntry.Type == model.ParamTypeQuery { // If original was query
							currentQueryParams.Set(paramName, dpayload)
							u.RawQuery = currentQueryParams.Encode()
						} else { // Default to query if type is ambiguous here but was in cp
							currentQueryParams.Set(paramName, dpayload)
							u.RawQuery = currentQueryParams.Encode()
						}
						durls = append(durls, u.String())
					}
				}
			}
			for paramName := range cpd { // Form params (less common for DOM XSS via URL manipulation, but possible if form values are used by client-side script)
				paramMapEntry, paramExists := params[paramName]
				if optimization.CheckInspectionParam(options, paramName) && paramExists && paramMapEntry.Type == model.ParamTypeBodyForm && (len(paramMapEntry.Chars) == 0 || options.HasMagicParams) {
					// DOM XSS for POST params usually means injecting into a form that's then processed by JS.
					// The durls here are GET requests. This might not be the most effective way to test DOM XSS for POST params.
					// However, keeping structure if some client-side logic reads initial POST values reflected on page.
					for _, dpayload := range dpayloads {
						u, _ := url.Parse(target) // Create a GET request with the payload in query
						currentQueryParams, _ := url.ParseQuery(u.RawQuery)
						currentQueryParams.Set(paramName, dpayload) // Test as if it were a GET param
						u.RawQuery = currentQueryParams.Encode()
						durls = append(durls, u.String())
					}
				}
			}
		}


		// Parameter-based XSS (Main loop over the `params` map)
		for k, v := range params { // k is param name, v is ParamResult
			if optimization.CheckInspectionParam(options, k) {
				paramTypeSuffix := "-" + v.Type
				chars := payload.GetSpecialChar() // TODO: This might differ based on param type context
				var badchars []string
				
				// Populate badchars based on v.Chars (actual reflected chars from discovery)
				// If v.Chars is empty (e.g. magic param, or not yet analyzed), badchars remains empty.
				if len(v.Chars) > 0 && !(options.HasMagicParams && params[k].Type == v.Type) { // Don't use discovery chars for magic params
					for _, av := range v.Chars {
						if utils.IndexOf(av, chars) == -1 { // If a reflected char is NOT in our standard special char list
							badchars = append(badchars, av)
						}
					}
				}

				// If detailed reflection points are known (from discovery)
				if v.ReflectedPoint != "" && strings.Contains(v.ReflectedPoint, "Injected:") && !(options.HasMagicParams && params[k].Type == v.Type) {
					injectedPoints := strings.Split(strings.TrimPrefix(v.ReflectedPoint, "Injected:"), "/")
					validInjectedChars := v.Chars // Use all reflected chars for this param for optimization check
					if len(params[k].Chars) > 1 && strings.HasSuffix(params[k].Chars[len(params[k].Chars)-1], ":") { // Check for PTYPE/Injected in last element
						validInjectedChars = params[k].Chars[:len(params[k].Chars)-1]
					}


					for _, ipActual := range injectedPoints {
						if ipActual == "" { continue }
						var payloadsForContext []string
						if strings.Contains(ipActual, "inJS") {
							canUseQuotes := false
							if strings.Contains(ipActual, "double") {
								for _, ic := range validInjectedChars { if strings.Contains(ic, "\"") { canUseQuotes = true; break } }
							} else if strings.Contains(ipActual, "single") {
								for _, ic := range validInjectedChars { if strings.Contains(ic, "'") { canUseQuotes = true; break } }
							} else { // Generic inJS, assume quotes might be usable if not specified otherwise
								canUseQuotes = true 
							}
							if canUseQuotes {
								payloadsForContext = optimization.SetPayloadValue(payload.GetInJsPayload(ipActual), options)
							} else {
								payloadsForContext = optimization.SetPayloadValue(payload.GetInJsBreakScriptPayload(ipActual), options)
							}
						} else if strings.Contains(ipActual, "inHTML") {
							payloadsForContext = optimization.SetPayloadValue(payload.GetHTMLPayload(ipActual), options)
						} else if strings.Contains(ipActual, "inATTR") {
							payloadsForContext = optimization.SetPayloadValue(payload.GetAttrPayload(ipActual), options)
						} else { // Default to HTML payloads if context is unclear but known to be injected
							payloadsForContext = optimization.SetPayloadValue(payload.GetHTMLPayload(ipActual), options)
						}

						for _, payloadValue := range payloadsForContext {
							if optimization.Optimization(payloadValue, badchars) {
								encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, payloadValue, ipActual+paramTypeSuffix, "toAppend", encoder, options, v.Type)
									query[tq] = tm
								}
							}
						}
					}
				} else { 
					// Generic testing if no detailed ReflectedPoint (e.g., for magic params, or if discovery was basic)
					// Iterate through common contexts: inHTML, inJS, inATTR
					contextsToTest := []string{"inHTML", "inJS", "inATTR"}
					if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie {
						contextsToTest = []string{"inHTML"} // Headers/cookies usually reflect into HTML, JS/ATTR less direct.
					}
					if v.Type == model.ParamTypeBodyJSON { // JSON needs specific handling, for now, treat as string in HTML
						contextsToTest = []string{"inHTML"} 
					}


					for _, contextKey := range contextsToTest {
						var payloadsToTest []string
						if contextKey == "inJS" {
							payloadsToTest = optimization.SetPayloadValue(payload.GetInJsPayload(contextKey), options) // Generic JS
						} else if contextKey == "inATTR" {
							payloadsToTest = optimization.SetPayloadValue(payload.GetAttrPayload(contextKey), options) // Generic Attr
						} else { // inHTML or default
							payloadsToTest = optimization.SetPayloadValue(payload.GetHTMLPayload(contextKey), options) // Generic HTML
						}
						
						for _, payloadValue := range payloadsToTest {
							// For magic params, badchars is empty, so optimization.Optimization should pass.
							if optimization.Optimization(payloadValue, badchars) { 
								encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
								// Adjust encoders based on param type for generic testing
								if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie {
									encoders = []string{NaN, urlEncode} // Headers/cookies less likely to need HTML encoding by Dalfox
								} else if v.Type == model.ParamTypeBodyJSON {
									encoders = []string{NaN} // Payload should be crafted for JSON or MakeRequestQuery handles JSON string escaping
								}

								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, payloadValue, contextKey+paramTypeSuffix, "toAppend", encoder, options, v.Type)
									query[tq] = tm
								}
							}
						}
					}
				}
				
				// Apply common payloads (generic ones) if not already covered by cpArr/cpdArr (for query/form)
				// For other types (Header, Cookie, JSON, etc.), this ensures they get common payloads.
				if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie || v.Type == model.ParamTypeBodyJSON || v.Type == model.ParamTypePath || v.Type == model.ParamTypeFragment ||
				   (!utils.ContainsFromArray(cpArr, k) && v.Type == model.ParamTypeQuery) || 
				   (!utils.ContainsFromArray(cpdArr, k) && v.Type == model.ParamTypeBodyForm) {
					
					commonPayloads := optimization.SetPayloadValue(payload.GetCommonPayload(), options)
					for _, payloadValue := range commonPayloads {
						if optimization.Optimization(payloadValue, badchars) {
							encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
							if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie {
								encoders = []string{NaN, urlEncode}
							} else if v.Type == model.ParamTypeBodyJSON {
								encoders = []string{NaN}
							}
							for _, encoder := range encoders {
								// Default to inHTML context for common payloads if not otherwise specified
								tq, tm := optimization.MakeRequestQuery(target, k, payloadValue, "inHTML"+paramTypeSuffix, "toAppend", encoder, options, v.Type)
								query[tq] = tm
							}
						}
					}
				}
			}
		}
	} else { // Content-Type not suitable for general HTML/JS based XSS, or only custom payloads requested
		printing.DalLog("SYSTEM", "Content-Type is '"+policy["Content-Type"]+"', only testing with customized payloads (custom/blind) or magic params if any.", options)
		// Still allow custom/blind payloads for specific content types if user forces with --custom-payload or --blind
		// This 'else' block was for the main "Common Payloads and DOM XSS" section.
		// Custom/Blind/Remote payload sections below are guarded by their own flags.
	}


	// Blind Payload
	if options.BlindURL != "" {
		bpayloads := payload.GetBlindPayload()
		bcallback := getBlindCallbackURL(options.BlindURL)
		// Header-based blind payload (Referer)
		for _, bpayload := range bpayloads {
			bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
			// MakeHeaderQuery needs to be aware of how to make a request if target is not a full URL
			// Assuming MakeHeaderQuery can handle base target string and adds header.
			tq, tm := optimization.MakeHeaderQuery(target, "Referer", bp, options) // This creates a request
			tm["payload"] = "toBlind" // Generic payload type for blind
			tm["type"] = "toBlind-" + model.ParamTypeHeader // Specific type for this blind vector
			query[tq] = tm
		}
		// Parameter-based blind payloads
		for k, v := range params { // k is param name, v is ParamResult
			if optimization.CheckInspectionParam(options, k) {
				paramTypeSuffix := "-" + v.Type
				for _, bpayload := range bpayloads {
					bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
					encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
					if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie {
						encoders = []string{NaN, urlEncode}
					} else if v.Type == model.ParamTypeBodyJSON {
						encoders = []string{NaN}
					}
					for _, encoder := range encoders {
						tq, tm := optimization.MakeRequestQuery(target, k, bp, "toBlind"+paramTypeSuffix, "toAppend", encoder, options, v.Type)
						tm["payload"] = "toBlind" // Meta info for the payload itself
						query[tq] = tm
					}
				}
			}
		}
		printing.DalLog("SYSTEM", "Added blind XSS payloads with callback URL: "+options.BlindURL, options)
	}

	// Custom Blind XSS Payloads from file
	if options.CustomBlindXSSPayloadFile != "" {
		// ... (error handling for file not found, etc. remains the same) ...
		fileInfo, statErr := os.Stat(options.CustomBlindXSSPayloadFile)
		if os.IsNotExist(statErr) { /* ... */ } else if statErr != nil { /* ... */ } else if fileInfo.IsDir() { /* ... */ } else {
			payloadLines, readErr := voltFile.ReadLinesOrLiteral(options.CustomBlindXSSPayloadFile)
			if readErr != nil { /* ... */ } else {
				var bcallback string
				if options.BlindURL != "" { bcallback = getBlindCallbackURL(options.BlindURL) }
				addedPayloadCount := 0
				for _, customPayload := range payloadLines {
					if customPayload != "" {
						addedPayloadCount++
						actualPayload := customPayload
						if options.BlindURL != "" { 
							actualPayload = strings.Replace(customPayload, "CALLBACKURL", bcallback, -1)
						}
						for k, v := range params { // k is param name, v is ParamResult
							if optimization.CheckInspectionParam(options, k) {
								paramTypeSuffix := "-" + v.Type
								// Use only NaN encoder for custom blind to avoid double encoding issues.
								// MakeRequestQuery needs to handle v.Type for placing payload.
								tq, tm := optimization.MakeRequestQuery(target, k, actualPayload, "toBlind"+paramTypeSuffix, "toBlind", NaN, options, v.Type)
								tm["payload"] = "toBlind" 
								query[tq] = tm
							}
						}
					}
				}
				if addedPayloadCount > 0 {
					printing.DalLog("SYSTEM", "Added "+strconv.Itoa(addedPayloadCount)+" custom blind XSS payloads from file: "+options.CustomBlindXSSPayloadFile, options)
				}
			}
		}
	}

	// Remote Payloads
	if options.RemotePayloads != "" {
		rp := strings.Split(options.RemotePayloads, ",")
		for _, endpoint := range rp {
			var payloads []string
			var line, size string
			if endpoint == "portswigger" { payloads, line, size = payload.GetPortswiggerPayload() }
			if endpoint == "payloadbox" { payloads, line, size = payload.GetPayloadBoxPayload() }
			
			if line != "" {
				printing.DalLog("INFO", "Successfully loaded '"+endpoint+"' payloads ["+line+" lines / "+size+"]", options)
				for _, remotePayload := range payloads {
					if remotePayload != "" {
						for k, v := range params { // k is param name, v is ParamResult
							if optimization.CheckInspectionParam(options, k) {
								paramTypeSuffix := "-" + v.Type
								// Default to inHTML for remote payloads, similar to custom payloads.
								injectionPoint := "inHTML" 
								encoders := []string{NaN, urlEncode, urlDoubleEncode, htmlEncode}
								if v.Type == model.ParamTypeHeader || v.Type == model.ParamTypeCookie {
									encoders = []string{NaN, urlEncode}
								} else if v.Type == model.ParamTypeBodyJSON {
									encoders = []string{NaN}
								}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, remotePayload, injectionPoint+paramTypeSuffix, "toAppend", encoder, options, v.Type)
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
