package scanning

import (
	"compress/gzip"
	"io"
	"encoding/json" // Added for JSON parsing
	"io/ioutil"     // Will be used if goquery needs it, or removed if direct io/os is sufficient
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/verification"
	"github.com/hahwul/dalfox/v2/pkg/model"
	voltFile "github.com/hahwul/volt/file"
	vlogger "github.com/hahwul/volt/logger"
	voltUtils "github.com/hahwul/volt/util"
	"github.com/sirupsen/logrus"
)

var clientPool = sync.Pool{
	New: func() interface{} {
		return &http.Client{
			Timeout: time.Duration(30) * time.Second,
		}
	},
}

// processParams will need significant changes later to handle different param types for payload injection.
// For now, the focus is on ParameterAnalysis correctly populating the initial params map with types.
func processParams(target string, paramsQue chan model.ParamResult, results chan model.ParamResult, options model.Options, rl *rateLimiter, miningCheckerLine int, pLog *logrus.Entry, baseReq *http.Request) {
	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	for paramToTest := range paramsQue {
		if !optimization.CheckInspectionParam(options, paramToTest.Name) {
			printing.DalLog("DEBUG", "Skipping parameter "+paramToTest.Name+" of type "+paramToTest.Type+" due to ignore/uniq options", options)
			// Send to results chan anyway so it's counted in WaitGroup, but without reflection checks
			results <- paramToTest
			continue
		}

		printing.DalLog("DEBUG", "Mining scan for parameter '"+paramToTest.Name+"' of type '"+paramToTest.Type+"'", options)

		// TODO: This is where the major refactoring for payload injection based on paramToTest.Type is needed.
		// MakeRequestQuery is designed for URL/Body params. We'll need new logic for headers, cookies, path, JSON.
		// For now, we'll simulate a basic check for query/form params as a placeholder.
		// The actual reflection check logic will be part of a subsequent step.

		var tempURL *http.Request
		// var err error
		testPayload := "Dalfox" // Generic test payload

		// Simplified reflection check logic - THIS WILL BE REFINED
		vrs := false
		var code string
		var smap string

		// Placeholder: Assume query/form for now for reflection checking part
		// This part needs to be heavily adapted based on paramToTest.Type
		if paramToTest.Type == model.ParamTypeQuery || paramToTest.Type == model.ParamTypeBodyForm {
			// Use existing MakeRequestQuery for query/form
			tempURL, _ = optimization.MakeRequestQuery(target, paramToTest.Name, testPayload, "PA", "toAppend", "NaN", options)
			if tempURL == nil && baseReq != nil { // if target had no query, MakeRequestQuery might need base
				tempURL, _ = optimization.MakeRequestQuery(baseReq.URL.String(), paramToTest.Name, testPayload, "PA", "toAppend", "NaN", options)
			}
		} else if paramToTest.Type == model.ParamTypeHeader {
			// Logic for header injection
			// Create a new request, add/modify header
			req, _ := http.NewRequest(options.Method, target, nil) // Simplified
			if baseReq != nil {
				req, _ = http.NewRequest(options.Method, baseReq.URL.String(), baseReq.Body)
				for k, vv := range baseReq.Header {
					for _, v := range vv {
						req.Header.Add(k, v)
					}
				}
			}
			req.Header.Set(paramToTest.Name, testPayload)
			tempURL = req
		} else if paramToTest.Type == model.ParamTypeCookie {
			// Logic for cookie injection
			req, _ := http.NewRequest(options.Method, target, nil) // Simplified
			if baseReq != nil {
				req, _ = http.NewRequest(options.Method, baseReq.URL.String(), baseReq.Body)
				for k, vv := range baseReq.Header {
					for _, v := range vv {
						req.Header.Add(k, v)
					}
				}
			}
			req.AddCookie(&http.Cookie{Name: paramToTest.Name, Value: testPayload})
			tempURL = req
		} else if paramToTest.Type == model.ParamTypePath {
			// Path parameter injection is more complex.
			// Needs to substitute the specific path segment.
			// For now, this is a placeholder.
			// Example: if original path was /api/v1/USERID/data and USERID is paramToTest.Name
			// newPath = /api/v1/Dalfox/data
			// This requires knowing original path and which segment this param is.
			// We'll skip reflection for path for now, just acknowledge it.
			paramToTest.Reflected = false // Placeholder
			results <- paramToTest
			continue // Skip actual send for now
		} else {
			// Other types like JSON, XML, FRAGMENT also need specific request construction.
			paramToTest.Reflected = false // Placeholder
			results <- paramToTest
			continue // Skip actual send for now
		}

		if tempURL == nil {
			results <- paramToTest
			continue
		}

		rl.Block(tempURL.URL.Host)
		resbody, resp, _, vrsLocal, err := SendReq(tempURL, testPayload, options) // SendReq needs to handle *http.Request

		if err == nil {
			vrs = vrsLocal // Assign to outer vrs
			wafCheck, wafN := checkWAF(resp.Header, resbody)
			if wafCheck {
				options.WAF = true
				options.WAFName = wafN
				if options.WAFEvasion {
					options.Concurrence = 1
					options.Delay = 3
					printing.DalLog("INFO", "Setting worker=1, delay=3s for WAF-Evasion", options)
				}
			}
		}

		_, lineSum := verification.VerifyReflectionWithLine(resbody, testPayload)
		if miningCheckerLine == lineSum && paramToTest.Type == model.ParamTypeQuery { // lineSum check might be specific to query params
			pLog.Debug("Hit linesum for param: " + paramToTest.Name)
			pLog.Debug(lineSum)
		}

		if vrs {
			paramToTest.Reflected = true
			code = printing.CodeView(resbody, testPayload)
			if len(code) > 5 { // Ensure code is long enough
				code = code[:len(code)-5]
			}
			paramToTest.ReflectedCode = code

			pointer := optimization.Abstraction(resbody, testPayload)
			smap = "Injected: "
			tempSmap := make(map[string]int)
			for _, v := range pointer {
				tempSmap[v]++
			}
			for k, v := range tempSmap {
				smap += "/" + k + "(" + strconv.Itoa(v) + ")"
			}
			paramToTest.ReflectedPoint = smap

			// Character reflection checks (simplified for now, needs type awareness)
			var wgChar sync.WaitGroup
			chars := payload.GetSpecialChar()
			for _, c := range chars {
				wgChar.Add(1)
				char := c
				go func() {
					defer wgChar.Done()
					encoders := []string{"NaN", "urlEncode", "htmlEncode"} // Simplified encoders
					testCharPayload := "dalfox" + char

					var charReq *http.Request
					// This needs to be type-aware for constructing request with char payload
					if paramToTest.Type == model.ParamTypeQuery || paramToTest.Type == model.ParamTypeBodyForm {
						charReq, _ = optimization.MakeRequestQuery(target, paramToTest.Name, testCharPayload, "PA-"+paramToTest.Type, "toAppend", encoders[0], options)
						if charReq == nil && baseReq != nil {
							charReq, _ = optimization.MakeRequestQuery(baseReq.URL.String(), paramToTest.Name, testCharPayload, "PA-"+paramToTest.Type, "toAppend", encoders[0], options)
						}
					} else if paramToTest.Type == model.ParamTypeHeader {
						req, _ := http.NewRequest(options.Method, target, nil)
						if baseReq != nil {
							req, _ = http.NewRequest(options.Method, baseReq.URL.String(), baseReq.Body)
							for k, vv := range baseReq.Header {
								for _, v_ := range vv {
									req.Header.Add(k, v_)
								}
							}
						}
						req.Header.Set(paramToTest.Name, testCharPayload)
						charReq = req
					} else if paramToTest.Type == model.ParamTypeCookie {
						req, _ := http.NewRequest(options.Method, target, nil)
						if baseReq != nil {
							req, _ = http.NewRequest(options.Method, baseReq.URL.String(), baseReq.Body)
							for k, vv := range baseReq.Header {
								for _, v_ := range vv {
									req.Header.Add(k, v_)
								}
							}
						}
						req.AddCookie(&http.Cookie{Name: paramToTest.Name, Value: testCharPayload})
						charReq = req
					}
					// Add more types if needed for char reflection

					if charReq != nil {
						rl.Block(charReq.URL.Host)
						_, _, _, vrsChar, _ := SendReq(charReq, testCharPayload, options)
						if vrsChar {
							paramToTest.Chars = append(paramToTest.Chars, char)
						}
					}
				}()
			}
			wgChar.Wait()
			paramToTest.Chars = voltUtils.UniqueStringSlice(paramToTest.Chars)
		}
		results <- paramToTest
	}
}

const maxConcurrency = 1000 // Define a reasonable maximum limit to prevent excessive memory allocation

func ParameterAnalysis(target string, options model.Options, rl *rateLimiter) map[string]model.ParamResult {
	miningCheckerLine := 0
	vLog := vlogger.GetLogger(options.Debug)
	pLog := vLog.WithField("data1", "PA")

	params := make(map[string]model.ParamResult) // Key: paramName+"_"+paramType for uniqueness if names collide across types

	parsedURL, err := url.Parse(target)
	if err != nil {
		printing.DalLog("ERROR", "Failed to parse target URL for parameter analysis: "+target, options)
		return params
	}

	// Generate a base request for context (headers, method, etc.)
	// This base request won't have payloads yet but sets up the structure.
	baseReqBody := strings.NewReader(options.Data)
	if options.Method == "" { // Default to GET if not specified
		options.Method = http.MethodGet
	}
	baseReq, err := http.NewRequest(options.Method, target, baseReqBody)
	if err != nil {
		printing.DalLog("ERROR", "Failed to create base request: "+err.Error(), options)
		return params
	}
	// Populate headers from options
	for _, h := range options.Header {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			baseReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if options.UserAgent != "" {
		baseReq.Header.Set("User-Agent", options.UserAgent)
	}
	if options.Cookie != "" {
		baseReq.Header.Set("Cookie", options.Cookie)
	}
	// Set Content-Type for POST/PUT/etc if data is present and not already set
	if options.Data != "" && (options.Method == http.MethodPost || options.Method == http.MethodPut || options.Method == http.MethodPatch) {
		if baseReq.Header.Get("Content-Type") == "" {
			// Default to form-urlencoded, but this might need to be smarter
			// or rely on user specifying it in --header
			baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// 1. Query Parameters
	queryValues := parsedURL.Query()
	for name := range queryValues {
		paramKey := name + "_" + model.ParamTypeQuery
		params[paramKey] = model.ParamResult{Name: name, Type: model.ParamTypeQuery}
	}

	// 2. Path Parameters
	pathSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	for i, segment := range pathSegments {
		if segment != "" {
			paramName := "path" + strconv.Itoa(i+1) 
			paramKey := paramName + "_" + model.ParamTypePath + "_" + segment 
			params[paramKey] = model.ParamResult{
				Name:           paramName, 
				Value:          segment,   
				Type:           model.ParamTypePath,
				ReflectedPoint: "ORIGINAL_PATH_SEGMENT_INDEX:" + strconv.Itoa(i), 
			}
		}
	}

	// 3. Fragment Parameters (if query-like)
	if parsedURL.Fragment != "" {
		if strings.Contains(parsedURL.Fragment, "=") {
			fragmentQuery, err := url.ParseQuery(parsedURL.Fragment)
			if err == nil {
				for name := range fragmentQuery {
					paramKey := name + "_" + model.ParamTypeFragment
					params[paramKey] = model.ParamResult{Name: name, Type: model.ParamTypeFragment}
				}
			}
		} else {
			paramKey := "fragment_full_" + model.ParamTypeFragment
			params[paramKey] = model.ParamResult{Name: "fragment_full", Type: model.ParamTypeFragment, Value: parsedURL.Fragment}
		}
	}

	// 4. Header Parameters
	if options.UserAgent != "" && baseReq.Header.Get("User-Agent") == options.UserAgent {
		paramKey := "User-Agent_" + model.ParamTypeHeader
		params[paramKey] = model.ParamResult{Name: "User-Agent", Type: model.ParamTypeHeader}
	}
	paramKeyReferer := "Referer_" + model.ParamTypeHeader
	params[paramKeyReferer] = model.ParamResult{Name: "Referer", Type: model.ParamTypeHeader}

	for _, h := range options.Header {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerName := strings.TrimSpace(parts[0])
			if strings.ToLower(headerName) != "cookie" && strings.ToLower(headerName) != "user-agent" && strings.ToLower(headerName) != "content-type" {
				paramKey := headerName + "_" + model.ParamTypeHeader
				params[paramKey] = model.ParamResult{Name: headerName, Type: model.ParamTypeHeader}
			}
		}
	}

	// 5. Cookie Parameters
	if options.Cookie != "" {
		header := http.Header{}
		header.Add("Cookie", options.Cookie)
		request := http.Request{Header: header}
		for _, cookie := range request.Cookies() {
			paramKey := cookie.Name + "_" + model.ParamTypeCookie
			params[paramKey] = model.ParamResult{Name: cookie.Name, Type: model.ParamTypeCookie}
		}
	}

	// 6. Body Parameters (Form, JSON)
	contentType := baseReq.Header.Get("Content-Type")
	if options.Data != "" {
		if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
			bodyParams, err := url.ParseQuery(options.Data)
			if err == nil {
				for name := range bodyParams {
					paramKey := name + "_" + model.ParamTypeBodyForm
					params[paramKey] = model.ParamResult{Name: name, Type: model.ParamTypeBodyForm}
				}
			}
		} else if strings.HasPrefix(contentType, "application/json") {
			var jsonData map[string]interface{}
			err := json.Unmarshal([]byte(options.Data), &jsonData)
			if err == nil {
				for key := range jsonData { 
					paramKey := key + "_" + model.ParamTypeBodyJSON
					params[paramKey] = model.ParamResult{Name: key, Type: model.ParamTypeBodyJSON}
				}
			} else {
				printing.DalLog("WARNING", "Failed to parse JSON body for parameter analysis: "+err.Error(), options)
			}
		} else if strings.HasPrefix(contentType, "application/xml") || strings.HasPrefix(contentType, "text/xml") {
			printing.DalLog("INFO", "XML body detected. Advanced XML parameter mining not yet implemented for individual tags/attributes.", options)
		}
	}

	if options.Mining {
		tempTargetForLineCheck := target
		if !strings.Contains(target, "?") {
			tempTargetForLineCheck = target + "?" 
		}
		tempURLReq, _ := optimization.MakeRequestQuery(tempTargetForLineCheck, "pleasedonthaveanamelikethis_plz_plz", "Dalfox", "PA", "toAppend", "NaN", options)
		if tempURLReq != nil {
			rl.Block(tempURLReq.URL.Host)
			resBody, _, _, vrs, _ := SendReq(tempURLReq, "Dalfox", options)
			if vrs {
				_, lineSum := verification.VerifyReflectionWithLine(resBody, "Dalfox")
				miningCheckerLine = lineSum
			}
		}
	}

	tempQueryHolder := make(url.Values)
	// tempFormHolder  := make(url.Values) // Not directly used, assuming mined params are query or DOM->query/form

	if options.Mining {
		if len(options.UniqParam) > 0 { 
			for _, up := range options.UniqParam {
				tempQueryHolder.Set(up, "")
			}
		}

		if options.MiningWordlist == "" {
			for _, mw := range payload.GetGfXSS() {
				tempQueryHolder.Set(mw, "")
			}
		} else {
			ff, err := voltFile.ReadLinesOrLiteral(options.MiningWordlist)
			if err != nil {
				printing.DalLog("SYSTEM", "Failed to load mining parameter wordlist", options)
			} else {
				for _, mw := range ff {
					tempQueryHolder.Set(mw, "")
				}
			}
		}

		if options.RemoteWordlists != "" {
			rw := strings.Split(options.RemoteWordlists, ",")
			for _, endpoint := range rw {
				var wordlist []string
				var line, size string
				if endpoint == "burp" {
					wordlist, line, size = payload.GetBurpWordlist()
				} else if endpoint == "assetnote" {
					wordlist, line, size = payload.GetAssetnoteWordlist()
				}
				if line != "" {
					printing.DalLog("INFO", "Successfully loaded '"+endpoint+"' wordlist ["+line+" lines / "+size+"] for query params", options)
					for _, mw := range wordlist {
						tempQueryHolder.Set(mw, "")
					}
				}
			}
		}
	}

	for name := range tempQueryHolder {
		paramKey := name + "_" + model.ParamTypeQuery 
		if _, exists := params[paramKey]; !exists { 
			params[paramKey] = model.ParamResult{Name: name, Type: model.ParamTypeQuery}
		}
	}

	if options.FindingDOM {
		domFoundParams := findDOMParamNames(target, options) 
		for _, name := range domFoundParams {
			paramKeyQuery := name + "_" + model.ParamTypeQuery
			if _, exists := params[paramKeyQuery]; !exists {
				params[paramKeyQuery] = model.ParamResult{Name: name, Type: model.ParamTypeQuery}
				printing.DalLog("DEBUG", "Found '"+name+"' from DOM, adding as Query param for test", options)
			}
			// Consider if options.Data implies these could be form params
			if options.Data != "" || options.Method == http.MethodPost || options.Method == http.MethodPut {
				paramKeyForm := name + "_" + model.ParamTypeBodyForm
				if _, exists := params[paramKeyForm]; !exists {
					params[paramKeyForm] = model.ParamResult{Name: name, Type: model.ParamTypeBodyForm}
					printing.DalLog("DEBUG", "Found '"+name+"' from DOM, adding as Form param for test (due to POST/PUT method or data presence)", options)
				}
			}
		}
	}

	var wg sync.WaitGroup
	concurrency := options.Concurrence
	if concurrency > maxConcurrency { 
		concurrency = maxConcurrency
	}

	paramsQue := make(chan model.ParamResult, len(params))
	resultsChan := make(chan model.ParamResult, len(params))

	processedParams := make(map[string]model.ParamResult) 

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processParams(target, paramsQue, resultsChan, options, rl, miningCheckerLine, pLog, baseReq)
		}()
	}

	for _, param := range params {
		paramsQue <- param
	}
	close(paramsQue)

	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range resultsChan {
			paramKey := result.Name + "_" + result.Type
			if result.Type == model.ParamTypePath { 
				// Path params were keyed with original segment value for uniqueness during initial population
				// Need to reconstruct this key if original value is part of result.Value
				// For now, assume result.Name is the unique "pathX" and result.Value is original segment
				originalSegment := result.Value // Assuming result.Value holds the original path segment
				if originalSegment == "" && strings.HasPrefix(result.ReflectedPoint, "ORIGINAL_PATH_SEGMENT_INDEX:") {
					// If Value isn't directly passed through, try to retrieve it if stored in ReflectedPoint initially
					// This part is a bit of a hack due to how path params were keyed.
					// Ideally, the original unique key or enough info to reconstruct it should be passed in ParamResult.
				}
				// This keying needs to be consistent with how it was added.
				// If result.Name is "path1", result.Value is "api", then key was "path1_PATH_api"
				paramKey = result.Name + "_" + result.Type + "_" + result.Value
			}


			existing, ok := processedParams[paramKey]
			if ok {
				existing.Reflected = existing.Reflected || result.Reflected
				if result.Reflected { 
					existing.ReflectedPoint = result.ReflectedPoint
					existing.ReflectedCode = result.ReflectedCode
				}
				for _, char := range result.Chars {
					if !voltUtils.StringInSlice(char, existing.Chars) {
						existing.Chars = append(existing.Chars, char)
					}
				}
				processedParams[paramKey] = existing
			} else {
				processedParams[paramKey] = result
			}
		}
	}()

	wg.Wait() 
	close(resultsChan) 
	collectorWg.Wait() 

	finalResults := make(map[string]model.ParamResult)
	for _, res := range processedParams {
		// If a param was not reflected and has no special chars, and is not a structural one like PATH, skip.
		if !res.Reflected && len(res.Chars) == 0 && res.Type != model.ParamTypePath {
			continue
		}

		existing, exists := finalResults[res.Name]
		if exists {
			// Prioritization logic: if new one is reflected and old one wasn't, replace.
			// Or, if types are different, decide. For now, simpler: reflected ones take precedence.
			if !existing.Reflected && res.Reflected {
				finalResults[res.Name] = res
			} else if existing.Reflected && res.Reflected {
				// If both are reflected, could merge Chars, or prioritize (e.g. Query over Header if names clash)
				// For now, let's merge Chars from both if they have same name but were processed as different types (e.g. same name in query and header)
				// This situation should be rare if keys in processedParams are type-specific (name_type)
				// The current finalResults key is just res.Name, so collisions are possible.
				mergedChars := existing.Chars
				for _, char := range res.Chars {
					if !voltUtils.StringInSlice(char, mergedChars) {
						mergedChars = append(mergedChars, char)
					}
				}
				finalResults[res.Name].Chars = mergedChars
				// Potentially log a warning about name collision if types were different
				if existing.Type != res.Type {
					printing.DalLog("DEBUG", "Parameter name '"+res.Name+"' found in multiple locations/types. Consolidating.", options)
				}
			}
		} else {
			finalResults[res.Name] = res
		}
	}

	if options.WAF {
		printing.DalLog("INFO", "Detected WAF: "+options.WAFName, options)
	}
	return finalResults
}

// findDOMParamNames is a refactored version of findDOMParams to return just names.
func findDOMParamNames(target string, options model.Options) []string {
	var names []string
	treq := optimization.GenerateNewRequest(target, "", options) // GenerateNewRequest will use options.Method
	if treq == nil {
		printing.DalLog("WARNING", "Failed to generate request for DOM mining.", options)
		return names
	}

	client := &http.Client{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Transport: getTransport(options),
	}
	if !options.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse 
		}
	}

	tres, err := client.Do(treq)
	if err != nil {
		printing.DalLog("WARNING", "Error during DOM request for parameter mining: "+err.Error(), options)
		return names
	}
	defer tres.Body.Close()

	var reader io.ReadCloser
	switch tres.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(tres.Body)
		if err != nil {
			printing.DalLog("WARNING", "Error creating gzip reader for DOM mining: "+err.Error(), options)
			reader = tres.Body 
		} else {
			defer reader.Close()
		}
	default:
		reader = tres.Body
	}

	bodyString, readErr := io.ReadAll(reader)
	if readErr != nil {
		printing.DalLog("WARNING", "Error reading response body for DOM mining: "+readErr.Error(), options)
		return names
	}

	doc, docErr := goquery.NewDocumentFromReader(strings.NewReader(string(bodyString)))
	if docErr != nil {
		printing.DalLog("WARNING", "Error parsing HTML for DOM mining: "+docErr.Error(), options)
		return names
	}

	seenNames := make(map[string]bool)
	doc.Find("input, textarea, select").Each(func(i int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if exists && name != "" && !seenNames[name] {
			names = append(names, name)
			seenNames[name] = true
		}
		id, exists := s.Attr("id")
		if exists && id != "" && !seenNames[id] { 
			names = append(names, id)
			seenNames[id] = true
		}
	})
	// Consider 'form' action attributes or 'a' hrefs if they might reveal parameters
	// This part is complex and application-specific, keeping it simple for now.
	if len(names) > 0 {
		printing.DalLog("INFO", "Found "+strconv.Itoa(len(names))+" potential testing points (names/ids) in DOM-based parameter mining", options)
	} else {
		printing.DalLog("INFO", "No input/textarea/select names or ids found in DOM for mining.", options)
	}
	return names
}

// GetPType is Get Parameter Type - This might be deprecated or heavily refactored.
// For now, let's keep it but note its potential obsolescence.
func GetPType(av string) string {
	if strings.Contains(av, "PTYPE: URL") { // Corresponds to ParamTypeQuery
		return "-" + model.ParamTypeQuery
	}
	if strings.Contains(av, "PTYPE: FORM") { // Corresponds to ParamTypeBodyForm
		return "-" + model.ParamTypeBodyForm
	}
	// This function was used to append to a string like "inHTML-URL".
	// With explicit types, the type itself is the primary info.
	return "" // Default if no old PTYPE marker found
}
