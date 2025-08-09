package scanning

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
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

func setP(p, dp url.Values, name string, options model.Options) (url.Values, url.Values) {
	if p.Get(name) == "" {
		p.Set(name, "")
	}
	if options.Data != "" {
		if dp.Get(name) == "" {
			dp.Set(name, "")
		}
	}
	return p, dp
}

func parseURL(target string) (*url.URL, url.Values, url.Values, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, nil, err
	}
	p, _ := url.ParseQuery(u.RawQuery)
	dp := url.Values{}
	return u, p, dp, nil
}

func addParamsFromWordlist(p, dp url.Values, wordlist []string, options model.Options) (url.Values, url.Values) {
	for _, param := range wordlist {
		if param != "" {
			p, dp = setP(p, dp, param, options)
		}
	}
	return p, dp
}

func addParamsFromRemoteWordlists(p, dp url.Values, options model.Options) (url.Values, url.Values) {
	rw := strings.Split(options.RemoteWordlists, ",")
	for _, endpoint := range rw {
		var wordlist []string
		var line, size string
		switch endpoint {
		case "burp":
			wordlist, line, size = payload.GetBurpWordlist()
		case "assetnote":
			wordlist, line, size = payload.GetAssetnoteWordlist()
		}
		if line != "" {
			printing.DalLog("INFO", "Successfully loaded '"+endpoint+"' wordlist ["+line+" lines / "+size+"]", options)
			p, dp = addParamsFromWordlist(p, dp, wordlist, options)
		}
	}
	return p, dp
}

// isJSONData checks if the provided data string is valid JSON
func isJSONData(data string) bool {
	data = strings.TrimSpace(data)
	if data == "" {
		return false
	}
	var jsonData interface{}
	err := json.Unmarshal([]byte(data), &jsonData)
	return err == nil && (strings.HasPrefix(data, "{") || strings.HasPrefix(data, "["))
}

// extractJSONParams recursively extracts parameter paths from JSON data
func extractJSONParams(data interface{}, path string, params map[string]model.ParamResult) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			currentPath := path
			if currentPath != "" {
				currentPath += "."
			}
			currentPath += key

			// Add this parameter path
			params[currentPath] = model.ParamResult{
				Name:      currentPath,
				Type:      "JSON",
				Reflected: true, // Assume reflected for JSON params
				Chars:     append(payload.GetSpecialChar(), "PTYPE: JSON"), // Add ptype marker
			}

			// Recursively process nested structures
			extractJSONParams(value, currentPath, params)
		}

	case []interface{}:
		for i, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, i)
			
			// Add array index parameter
			params[currentPath] = model.ParamResult{
				Name:      currentPath,
				Type:      "JSON",
				Reflected: true,
				Chars:     append(payload.GetSpecialChar(), "PTYPE: JSON"), // Add ptype marker
			}

			// Recursively process array items
			extractJSONParams(item, currentPath, params)
		}
	}
}

// findJSONParams analyzes JSON data and extracts testable parameters
func findJSONParams(params map[string]model.ParamResult, options model.Options) map[string]model.ParamResult {
	if options.Data == "" || !isJSONData(options.Data) {
		return params
	}

	printing.DalLog("SYSTEM", "Detected JSON body data - extracting JSON parameters", options)
	
	var jsonData interface{}
	err := json.Unmarshal([]byte(options.Data), &jsonData)
	if err != nil {
		printing.DalLog("ERROR", "Failed to parse JSON data: "+err.Error(), options)
		return params
	}

	// Extract JSON parameters
	extractJSONParams(jsonData, "", params)
	
	jsonParamCount := 0
	for _, param := range params {
		if param.Type == "JSON" {
			jsonParamCount++
		}
	}
	
	if jsonParamCount > 0 {
		printing.DalLog("INFO", "Found "+strconv.Itoa(jsonParamCount)+" JSON parameters for testing", options)
	}
	
	return params
}

func findDOMParams(target string, p, dp url.Values, options model.Options) (url.Values, url.Values) {
	treq := optimization.GenerateNewRequest(target, "", options)
	if treq != nil {
		client := &http.Client{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			Transport: getTransport(options),
		}
		if !options.FollowRedirect {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return nil
			}
		}
		tres, err := client.Do(treq)
		if err == nil {
			defer tres.Body.Close()
			var reader io.ReadCloser
			switch tres.Header.Get("Content-Encoding") {
			case "gzip":
				reader, err = gzip.NewReader(tres.Body)
				if err != nil {
					reader = tres.Body
				}
				defer reader.Close()
			default:
				reader = tres.Body
			}
			bodyString, err := io.ReadAll(reader)
			if err == nil {
				body := ioutil.NopCloser(strings.NewReader(string(bodyString)))
				defer body.Close()
				doc, err := goquery.NewDocumentFromReader(body)
				if err == nil {
					count := 0
					doc.Find("input, textarea, select, form, a").Each(func(i int, s *goquery.Selection) {
						name, _ := s.Attr("name")
						if name == "" {
							name, _ = s.Attr("action")
						}
						if name == "" {
							name, _ = s.Attr("href")
						}
						if name != "" {
							p, dp = setP(p, dp, name, options)
							count++
						}
					})
					printing.DalLog("INFO", "Found "+strconv.Itoa(count)+" testing points in DOM-based parameter mining", options)
				}
			}
		}
	}
	return p, dp
}

func processParams(target string, paramsQue chan string, results chan model.ParamResult, options model.Options, rl *rateLimiter, miningCheckerLine int, pLog *logrus.Entry) {
	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)
	for k := range paramsQue {
		if optimization.CheckInspectionParam(options, k) {
			printing.DalLog("DEBUG", "Mining URL scan for parameter "+k, options)
			tempURL, _ := optimization.MakeRequestQuery(target, k, "Dalfox", "PA", "toAppend", "NaN", options)
			var code string
			rl.Block(tempURL.Host)
			resbody, resp, _, vrs, err := SendReq(tempURL, "Dalfox", options)
			if err == nil {
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
			_, lineSum := verification.VerifyReflectionWithLine(resbody, "Dalfox")
			if miningCheckerLine == lineSum {
				pLog.Debug("Hit linesum")
				pLog.Debug(lineSum)
			}
			if vrs {
				code = printing.CodeView(resbody, "Dalfox")
				code = code[:len(code)-5]
				pointer := optimization.Abstraction(resbody, "Dalfox")
				smap := "Injected: "
				tempSmap := make(map[string]int)
				for _, v := range pointer {
					tempSmap[v]++
				}
				for k, v := range tempSmap {
					smap += "/" + k + "(" + strconv.Itoa(v) + ")"
				}
				paramResult := model.ParamResult{
					Name:           k,
					Type:           "URL",
					Reflected:      true,
					ReflectedPoint: smap,
					ReflectedCode:  code,
				}
				var wg sync.WaitGroup
				chars := payload.GetSpecialChar()
				for _, c := range chars {
					wg.Add(1)
					char := c
					go func() {
						defer wg.Done()
						encoders := []string{
							"NaN",
							"urlEncode",
							"urlDoubleEncode",
							"htmlEncode",
						}
						for _, encoder := range encoders {
							turl, _ := optimization.MakeRequestQuery(target, k, "dalfox"+char, "PA-URL", "toAppend", encoder, options)
							rl.Block(tempURL.Host)
							_, _, _, vrs, _ := SendReq(turl, "dalfox"+char, options)
							if vrs {
								paramResult.Chars = append(paramResult.Chars, char)
							}
						}
					}()
				}
				wg.Wait()
				paramResult.Chars = voltUtils.UniqueStringSlice(paramResult.Chars)
				results <- paramResult
			}
		}
	}
}

func ParameterAnalysis(target string, options model.Options, rl *rateLimiter) map[string]model.ParamResult {
	miningCheckerLine := 0
	vLog := vlogger.GetLogger(options.Debug)
	pLog := vLog.WithField("data1", "PA")
	_, p, dp, err := parseURL(target)
	params := make(map[string]model.ParamResult)
	if err != nil {
		return params
	}

	for tempP := range p {
		params[tempP] = model.ParamResult{}
	}

	// JSON Body Parameter Discovery
	params = findJSONParams(params, options)

	if options.Mining {
		tempURL, _ := optimization.MakeRequestQuery(target, "pleasedonthaveanamelikethis_plz_plz", "Dalfox", "PA", "toAppend", "NaN", options)
		rl.Block(tempURL.Host)
		resBody, _, _, vrs, _ := SendReq(tempURL, "Dalfox", options)
		if vrs {
			_, lineSum := verification.VerifyReflectionWithLine(resBody, "Dalfox")
			miningCheckerLine = lineSum
		}

		if len(options.UniqParam) > 0 {
			p, dp = addParamsFromWordlist(p, dp, options.UniqParam, options)
		}

		// Enhanced parameter mining for DetailedAnalysis (Issue #695)
		if options.DetailedAnalysis {
			printing.DalLog("SYSTEM", "Detailed analysis enabled - using extended parameter wordlists", options)
			// Add more comprehensive parameter lists for detailed analysis
			extendedParams := append(payload.GetGfXSS(), []string{
				"callback", "jsonp", "api_key", "access_token", "csrf_token", "session_id",
				"user_id", "admin", "debug", "test", "dev", "staging", "prod",
				"config", "settings", "options", "params", "data", "input",
				"output", "result", "response", "request", "query", "search",
				"filter", "sort", "order", "limit", "offset", "page", "size",
			}...)
			p, dp = addParamsFromWordlist(p, dp, extendedParams, options)
		} else if options.MiningWordlist == "" {
			p, dp = addParamsFromWordlist(p, dp, payload.GetGfXSS(), options)
		} else {
			ff, err := voltFile.ReadLinesOrLiteral(options.MiningWordlist)
			if err != nil {
				printing.DalLog("SYSTEM", "Failed to load mining parameter wordlist", options)
			} else {
				p, dp = addParamsFromWordlist(p, dp, ff, options)
			}
		}

		if options.RemoteWordlists != "" {
			p, dp = addParamsFromRemoteWordlists(p, dp, options)
		}
	}

	if options.FindingDOM {
		p, dp = findDOMParams(target, p, dp, options)
	}

	var wgg sync.WaitGroup
	const maxConcurrency = 1000 // Define a reasonable maximum limit to prevent excessive memory allocation
	concurrency := options.Concurrence

	// FastScan optimization (Issue #764)
	if options.FastScan {
		printing.DalLog("SYSTEM", "Fast scan mode enabled - optimizing concurrency and reducing checks", options)
		// Increase concurrency for faster scanning
		if concurrency < 50 {
			concurrency = 50
		}
		// Limit parameter mining in fast mode
		if len(p) > 20 {
			printing.DalLog("INFO", "Fast scan mode: limiting parameter analysis to first 20 parameters", options)
			count := 0
			limitedP := make(url.Values)
			for k, v := range p {
				if count >= 20 {
					break
				}
				limitedP[k] = v
				count++
			}
			p = limitedP
		}
	}

	if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}
	paramsQue := make(chan string, concurrency)
	results := make(chan model.ParamResult, concurrency)
	miningDictCount := 0
	mutex := &sync.Mutex{}

	go func() {
		for result := range results {
			mutex.Lock()
			params[result.Name] = result
			mutex.Unlock()
		}
	}()

	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			processParams(target, paramsQue, results, options, rl, miningCheckerLine, pLog)
			wgg.Done()
		}()
	}

	for v := range p {
		if len(options.UniqParam) > 0 {
			for _, selectedParam := range options.UniqParam {
				if selectedParam == v {
					paramsQue <- v
				}
			}
		} else if len(options.IgnoreParams) > 0 {
			for _, ignoreParam := range options.IgnoreParams {
				if ignoreParam != v {
					paramsQue <- v
				}
			}
		} else {
			paramsQue <- v
		}
	}

	close(paramsQue)
	wgg.Wait()
	close(results)

	var wggg sync.WaitGroup
	paramsDataQue := make(chan string, concurrency)
	for j := 0; j < concurrency; j++ {
		wggg.Add(1)
		go func() {
			processParams(target, paramsDataQue, results, options, rl, miningCheckerLine, pLog)
			wggg.Done()
		}()
	}

	for v := range dp {
		if len(options.UniqParam) > 0 {
			for _, selectedParam := range options.UniqParam {
				if selectedParam == v {
					paramsDataQue <- v
				}
			}
		} else {
			paramsDataQue <- v
		}
	}

	close(paramsDataQue)
	wggg.Wait()
	if miningDictCount != 0 {
		printing.DalLog("INFO", "Found "+strconv.Itoa(miningDictCount)+" testing points in dictionary-based parameter mining", options)
	}
	if options.WAF {
		printing.DalLog("INFO", "Detected WAF: "+options.WAFName, options)
	}
	return params
}

// GetPType is Get Parameter Type
func GetPType(av string) string {
	if strings.Contains(av, "PTYPE: URL") {
		return "-URL"
	}
	if strings.Contains(av, "PTYPE: FORM") {
		return "-FORM"
	}
	if strings.Contains(av, "PTYPE: QUERY") {
		return "-QUERY"
	}
	if strings.Contains(av, "PTYPE: PATH") {
		return "-PATH"
	}
	if strings.Contains(av, "PTYPE: HASH") {
		return "-HASH"
	}
	if strings.Contains(av, "PTYPE: HEADER") {
		return "-HEADER"
	}
	if strings.Contains(av, "PTYPE: COOKIE") {
		return "-COOKIE"
	}
	if strings.Contains(av, "PTYPE: JSON") {
		return "-JSON"
	}
	if strings.Contains(av, "PTYPE: XML") {
		return "-XML"
	}
	if strings.Contains(av, "PTYPE: DOM") {
		return "-DOM"
	}
	if strings.Contains(av, "PTYPE: JS_VAR") {
		return "-JS_VAR"
	}
	if strings.Contains(av, "PTYPE: JS_STRING") {
		return "-JS_STRING"
	}
	if strings.Contains(av, "PTYPE: ATTRIBUTE") {
		return "-ATTRIBUTE"
	}
	return ""
}

// DOMXSSDetector handles DOM-based XSS detection
type DOMXSSDetector struct {
	Sources []string
	Sinks   []string
}

// NewDOMXSSDetector creates a new DOM XSS detector with predefined sources and sinks
func NewDOMXSSDetector() *DOMXSSDetector {
	return &DOMXSSDetector{
		Sources: []string{
			"location.href",
			"location.search",
			"location.hash",
			"location.pathname",
			"document.URL",
			"document.documentURI",
			"document.baseURI",
			"window.name",
			"document.referrer",
			"document.cookie",
			"localStorage",
			"sessionStorage",
			"history.pushState",
			"history.replaceState",
			"postMessage",
			"XMLHttpRequest",
			"fetch",
			"WebSocket",
		},
		Sinks: []string{
			"innerHTML",
			"outerHTML",
			"document.write",
			"document.writeln",
			"eval",
			"setTimeout",
			"setInterval",
			"Function",
			"execScript",
			"msSetImmediate",
			"range.createContextualFragment",
			"crypto.generateCRMFRequest",
			"ScriptElement.src",
			"ScriptElement.text",
			"ScriptElement.textContent",
			"ScriptElement.innerText",
			"anyTag.onEventName",
			"document.implementation.createHTMLDocument",
			"history.pushState",
			"history.replaceState",
		},
	}
}

// DetectDOMXSS analyzes JavaScript code for potential DOM XSS vulnerabilities
func (d *DOMXSSDetector) DetectDOMXSS(jsCode string) []map[string]interface{} {
	var vulnerabilities []map[string]interface{}

	// Check for direct source to sink flows
	for _, source := range d.Sources {
		for _, sink := range d.Sinks {
			// Simple pattern matching for source to sink flow
			pattern := fmt.Sprintf("%s.*%s", source, sink)
			if matched, _ := regexp.MatchString(pattern, jsCode); matched {
				vulnerabilities = append(vulnerabilities, map[string]interface{}{
					"type":        "DOM_XSS",
					"source":      source,
					"sink":        sink,
					"pattern":     pattern,
					"description": fmt.Sprintf("Potential DOM XSS: %s flows to %s", source, sink),
				})
			}
		}
	}

	// Check for dangerous patterns
	dangerousPatterns := []map[string]string{
		{"pattern": `document\.write\s*\(.*location\.(href|search|hash)`, "desc": "document.write with location data"},
		{"pattern": `innerHTML\s*=.*location\.(href|search|hash)`, "desc": "innerHTML assignment with location data"},
		{"pattern": `eval\s*\(.*location\.(href|search|hash)`, "desc": "eval with location data"},
		{"pattern": `setTimeout\s*\(.*location\.(href|search|hash)`, "desc": "setTimeout with location data"},
		{"pattern": `setInterval\s*\(.*location\.(href|search|hash)`, "desc": "setInterval with location data"},
		{"pattern": `Function\s*\(.*location\.(href|search|hash)`, "desc": "Function constructor with location data"},
		{"pattern": `\.src\s*=.*location\.(href|search|hash)`, "desc": "Script src assignment with location data"},
		{"pattern": `postMessage\s*\(.*location\.(href|search|hash)`, "desc": "postMessage with location data"},
	}

	for _, dangerousPattern := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dangerousPattern["pattern"], jsCode); matched {
			vulnerabilities = append(vulnerabilities, map[string]interface{}{
				"type":        "DOM_XSS_PATTERN",
				"pattern":     dangerousPattern["pattern"],
				"description": dangerousPattern["desc"],
			})
		}
	}

	return vulnerabilities
}

// ExtractJavaScript extracts JavaScript code from HTML content
func ExtractJavaScript(htmlContent string) []string {
	var jsCode []string

	// Extract inline script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>(.*?)</script>`)
	matches := scriptRegex.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			jsCode = append(jsCode, match[1])
		}
	}

	// Extract event handlers
	eventHandlers := []string{
		"onclick", "onload", "onmouseover", "onmouseout", "onfocus", "onblur",
		"onchange", "onsubmit", "onreset", "onselect", "onkeydown", "onkeyup",
		"onkeypress", "onerror", "onabort", "oncanplay", "oncanplaythrough",
		"ondurationchange", "onemptied", "onended", "onloadeddata",
		"onloadedmetadata", "onloadstart", "onpause", "onplay", "onplaying",
		"onprogress", "onratechange", "onseeked", "onseeking", "onstalled",
		"onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",
	}

	// Pre-compile regex patterns for better performance
	handlerPatterns := make([]*regexp.Regexp, len(eventHandlers))
	for i, handler := range eventHandlers {
		pattern := fmt.Sprintf(`(?i)%s\s*=\s*["']([^"']*)["']`, handler)
		handlerPatterns[i] = regexp.MustCompile(pattern)
	}

	// Find all event handler matches
	for _, handlerRegex := range handlerPatterns {
		handlerMatches := handlerRegex.FindAllStringSubmatch(htmlContent, -1)
		for _, match := range handlerMatches {
			if len(match) > 1 {
				jsCode = append(jsCode, match[1])
			}
		}
	}

	// Extract javascript: URLs
	jsURLRegex := regexp.MustCompile(`(?i)javascript:([^"'\s>]*)`)
	matches = jsURLRegex.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			jsCode = append(jsCode, match[1])
		}
	}

	return jsCode
}

// AnalyzeDOMXSS performs comprehensive DOM XSS analysis
func AnalyzeDOMXSS(htmlContent string, targetURL string) []map[string]interface{} {
	detector := NewDOMXSSDetector()
	jsCodeBlocks := ExtractJavaScript(htmlContent)

	var allVulnerabilities []map[string]interface{}

	for i, jsCode := range jsCodeBlocks {
		vulns := detector.DetectDOMXSS(jsCode)
		for _, vuln := range vulns {
			vuln["block_index"] = i
			vuln["js_code"] = jsCode
			vuln["target_url"] = targetURL
			allVulnerabilities = append(allVulnerabilities, vuln)
		}
	}

	return allVulnerabilities
}
