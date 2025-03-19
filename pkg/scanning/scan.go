package scanning

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/utils"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/report"
	"github.com/hahwul/dalfox/v2/internal/verification"
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
		printing.DalLog("SYSTEM", "Not running "+target+" url", options)
		return scanResult, err
	}
	treq := optimization.GenerateNewRequest(target, "", options)
	if treq == nil {
		return scanResult, fmt.Errorf("failed to generate initial request")
	}
	client := createHTTPClient(options)
	tres, err := client.Do(treq)
	if err != nil {
		msg := fmt.Sprintf("not running %v", err)
		printing.DalLog("ERROR", msg, options)
		return scanResult, err
	}
	if options.IgnoreReturn != "" {
		if shouldIgnoreReturn(tres.StatusCode, options.IgnoreReturn) {
			printing.DalLog("SYSTEM", "Not running "+target+" url from --ignore-return option", options)
			return scanResult, nil
		}
	}
	defer tres.Body.Close()
	body, err := io.ReadAll(tres.Body)
	if err != nil {
		return scanResult, err
	}
	printing.DalLog("SYSTEM", "Valid target [ code:"+strconv.Itoa(tres.StatusCode)+" / size:"+strconv.Itoa(len(body))+" ]", options)

	// 디스커버리 단계
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

// performDiscovery handles the discovery phase including static, parameter, and BAV analysis.
func performDiscovery(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string, map[string]model.ParamResult) {
	policy := make(map[string]string)
	pathReflection := make(map[int]string)
	params := make(map[string]model.ParamResult)

	var wait sync.WaitGroup
	task := 3
	sa := "SA: ✓ "
	pa := "PA: ✓ "
	bav := "BAV: ✓ "
	if !options.UseBAV {
		task = 2
		bav = ""
	}

	wait.Add(task)
	printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)

	go func() {
		defer wait.Done()
		policy, pathReflection = StaticAnalysis(target, options, rl)
		sa = options.AuroraObject.Green(sa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	go func() {
		defer wait.Done()
		params = ParameterAnalysis(target, options, rl)
		pa = options.AuroraObject.Green(pa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	if options.UseBAV {
		go func() {
			defer wait.Done()
			RunBAVAnalysis(target, options, rl, &bav)
		}()
	}

	if options.NowURL != 0 && !options.Silence {
		s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks] Scanning.."
	}
	if !(options.Silence || options.NoSpinner) {
		time.Sleep(1 * time.Second)
		s.Start()
	}
	wait.Wait()
	if !(options.Silence || options.NoSpinner) {
		s.Stop()
	}

	return policy, pathReflection, params
}

// generatePayloads generates XSS payloads based on discovery results.
func generatePayloads(target string, options model.Options, policy map[string]string, pathReflection map[int]string, params map[string]model.ParamResult) (map[*http.Request]map[string]string, []string) {
	query := make(map[*http.Request]map[string]string)
	var durls []string
	parsedURL, _ := url.Parse(target)

	printing.DalLog("SYSTEM", "Generate XSS payload and optimization.Optimization.. 🛠", options)

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
	if (options.SkipDiscovery || isAllowType(policy["Content-Type"])) && options.CustomPayloadFile != "" {
		ff, err := voltFile.ReadLinesOrLiteral(options.CustomPayloadFile)
		if err != nil {
			printing.DalLog("SYSTEM", "Custom XSS payload load fail..", options)
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
			printing.DalLog("SYSTEM", "Added your "+strconv.Itoa(len(ff))+" custom xss payload", options)
		}
	}

	// Common Payloads and DOM XSS
	if (options.SkipDiscovery || isAllowType(policy["Content-Type"])) && !options.OnlyCustomPayload {
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
	} else {
		printing.DalLog("SYSTEM", "Type is '"+policy["Content-Type"]+"', It does not test except customized payload (custom/blind).", options)
	}

	// Blind Payload
	if options.BlindURL != "" {
		bpayloads := payload.GetBlindPayload()
		var bcallback string
		if strings.HasPrefix(options.BlindURL, "https://") || strings.HasPrefix(options.BlindURL, "http://") {
			bcallback = options.BlindURL
		} else {
			bcallback = "//" + options.BlindURL
		}
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
						tq, tm := optimization.MakeRequestQuery(target, k, bp, "toBlind"+ptype, "toAppend", encoder, options)
						tm["payload"] = "toBlind"
						query[tq] = tm
					}
				}
			}
		}
		printing.DalLog("SYSTEM", "Added your blind XSS ("+options.BlindURL+")", options)
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
				printing.DalLog("INFO", "A '"+endpoint+"' payloads has been loaded ["+line+"L / "+size+"]               ", options)
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
				printing.DalLog("SYSTEM", endpoint+" payload load fail..", options)
			}
		}
	}

	return query, durls
}

// performScanning performs the scanning phase by sending requests and analyzing responses.
func performScanning(target string, options model.Options, query map[*http.Request]map[string]string, durls []string, rl *rateLimiter, vStatus map[string]bool) []model.PoC {
	var pocs []model.PoC
	queryCount := 0

	printing.DalLog("SYSTEM", "Start XSS Scanning.. with "+strconv.Itoa(len(query))+" queries 🗡", options)
	printing.DalLog("SYSTEM", "[ Make "+strconv.Itoa(options.Concurrence)+" workers ] [ Allocated "+strconv.Itoa(len(query))+" queries ]", options)

	if !(options.Silence || options.NoSpinner) {
		s.Start()
	}

	showR, showV := true, true
	if options.OnlyPoC != "" {
		_, showR, showV = printing.CheckToShowPoC(options.OnlyPoC)
	}

	var wg sync.WaitGroup
	concurrency := options.Concurrence
	queries := make(chan Queries)
	resultsChan := make(chan model.PoC)
	doneChan := make(chan bool)

	go func() {
		for result := range resultsChan {
			pocs = append(pocs, result)
		}
		doneChan <- true
	}()

	// DOM XSS 체크 (Headless 모드)
	if options.UseHeadless {
		wg.Add(1)
		go func() {
			dconcurrency := options.Concurrence / 2
			if dconcurrency < 1 {
				dconcurrency = 1
			}
			if dconcurrency > 10 {
				dconcurrency = 10
			}
			dchan := make(chan string)
			var wgg sync.WaitGroup
			for i := 0; i < dconcurrency; i++ {
				wgg.Add(1)
				go func() {
					for v := range dchan {
						if CheckXSSWithHeadless(v, options) {
							printing.DalLog("VULN", "Triggered XSS Payload (found dialog in headless)", options)
							poc := model.PoC{
								Type:       "V",
								InjectType: "headless",
								Method:     "GET",
								Data:       v,
								Param:      "",
								Payload:    "",
								Evidence:   "",
								CWE:        "CWE-79",
								Severity:   "High",
								PoCType:    options.PoCType,
								MessageStr: "Triggered XSS Payload (found dialog in headless)",
							}
							if showV {
								if options.Format == "json" {
									pocj, _ := json.Marshal(poc)
									printing.DalLog("PRINT", string(pocj)+",", options)
								} else {
									pocsStr := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
									printing.DalLog("PRINT", pocsStr, options)
								}
							}
							if options.FoundAction != "" {
								foundAction(options, target, v, "VULN")
							}
							resultsChan <- poc
						}
						queryCount++
					}
					wgg.Done()
				}()
			}
			for _, dchanData := range durls {
				dchan <- dchanData
			}
			close(dchan)
			wgg.Wait()
			wg.Done()
		}()
	}

	// HTTP 요청 워커
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for reqJob := range queries {
				if checkVStatus(vStatus) {
					continue
				}
				k := reqJob.request
				v := reqJob.metadata
				checkVtype := utils.CheckPType(v["type"])

				if !vStatus[v["param"]] || checkVtype {
					rl.Block(k.Host)
					resbody, _, vds, vrs, err := SendReq(k, v["payload"], options)
					abs := optimization.Abstraction(resbody, v["payload"])
					if vrs && !utils.ContainsFromArray(abs, v["type"]) && !strings.Contains(v["type"], "inHTML") {
						vrs = false
					}
					if err == nil {
						if strings.Contains(v["type"], "inJS") && vrs {
							protected := verification.VerifyReflection(resbody, "\\"+v["payload"]) && !strings.Contains(v["payload"], "\\")
							if !protected && !vStatus[v["param"]] {
								if options.UseHeadless && CheckXSSWithHeadless(k.URL.String(), options) {
									poc := model.PoC{
										Type:       "V",
										InjectType: v["type"],
										Method:     k.Method,
										Data:       printing.MakePoC(k.URL.String(), k, options),
										Param:      v["param"],
										Payload:    "",
										Evidence:   "",
										CWE:        "CWE-79",
										Severity:   "High",
										PoCType:    options.PoCType,
										MessageID:  har.MessageIDFromRequest(k),
										MessageStr: "Triggered XSS Payload (found dialog in headless)",
									}
									logPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found dialog in headless)")
									vStatus[v["param"]] = true
									if options.FoundAction != "" {
										foundAction(options, target, k.URL.String(), "VULN")
									}
									resultsChan <- poc
								} else {
									poc := model.PoC{
										Type:       "R",
										InjectType: v["type"],
										Method:     k.Method,
										Data:       printing.MakePoC(k.URL.String(), k, options),
										Param:      v["param"],
										Payload:    v["payload"],
										Evidence:   printing.CodeView(resbody, v["payload"]),
										CWE:        "CWE-79",
										Severity:   "Medium",
										PoCType:    options.PoCType,
										MessageID:  har.MessageIDFromRequest(k),
										MessageStr: "Reflected Payload in JS: " + v["param"] + "=" + v["payload"],
									}
									logPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in JS: "+v["param"]+"="+v["payload"])
									if options.FoundAction != "" {
										foundAction(options, target, k.URL.String(), "WEAK")
									}
									resultsChan <- poc
								}
							}
						} else if strings.Contains(v["type"], "inATTR") {
							if vds && !vStatus[v["param"]] {
								poc := model.PoC{
									Type:       "V",
									InjectType: v["type"],
									Method:     k.Method,
									Data:       printing.MakePoC(k.URL.String(), k, options),
									Param:      v["param"],
									Payload:    v["payload"],
									Evidence:   printing.CodeView(resbody, v["payload"]),
									CWE:        "CWE-83",
									Severity:   "High",
									PoCType:    options.PoCType,
									MessageID:  har.MessageIDFromRequest(k),
									MessageStr: "Triggered XSS Payload (found DOM Object): " + v["param"] + "=" + v["payload"],
								}
								logPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"])
								vStatus[v["param"]] = true
								if options.FoundAction != "" {
									foundAction(options, target, k.URL.String(), "VULN")
								}
								resultsChan <- poc
							} else if vrs && !vStatus[v["param"]] {
								poc := model.PoC{
									Type:       "R",
									InjectType: v["type"],
									Method:     k.Method,
									Data:       printing.MakePoC(k.URL.String(), k, options),
									Param:      v["param"],
									Payload:    v["payload"],
									Evidence:   printing.CodeView(resbody, v["payload"]),
									CWE:        "CWE-83",
									Severity:   "Medium",
									PoCType:    options.PoCType,
									MessageID:  har.MessageIDFromRequest(k),
									MessageStr: "Reflected Payload in Attribute: " + v["param"] + "=" + v["payload"],
								}
								logPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in Attribute: "+v["param"]+"="+v["payload"])
								if options.FoundAction != "" {
									foundAction(options, target, k.URL.String(), "WEAK")
								}
								resultsChan <- poc
							}
						} else {
							if vds && !vStatus[v["param"]] {
								poc := model.PoC{
									Type:       "V",
									InjectType: v["type"],
									Method:     k.Method,
									Data:       printing.MakePoC(k.URL.String(), k, options),
									Param:      v["param"],
									Payload:    v["payload"],
									Evidence:   printing.CodeView(resbody, v["payload"]),
									CWE:        "CWE-79",
									Severity:   "High",
									PoCType:    options.PoCType,
									MessageID:  har.MessageIDFromRequest(k),
									MessageStr: "Triggered XSS Payload (found DOM Object): " + v["param"] + "=" + v["payload"],
								}
								logPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"])
								vStatus[v["param"]] = true
								if options.FoundAction != "" {
									foundAction(options, target, k.URL.String(), "VULN")
								}
								resultsChan <- poc
							} else if vrs && !vStatus[v["param"]] {
								poc := model.PoC{
									Type:       "R",
									InjectType: v["type"],
									Method:     k.Method,
									Data:       printing.MakePoC(k.URL.String(), k, options),
									Param:      v["param"],
									Payload:    v["payload"],
									Evidence:   printing.CodeView(resbody, v["payload"]),
									CWE:        "CWE-79",
									Severity:   "Medium",
									PoCType:    options.PoCType,
									MessageID:  har.MessageIDFromRequest(k),
									MessageStr: "Reflected Payload in HTML: " + v["param"] + "=" + v["payload"],
								}
								logPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in HTML: "+v["param"]+"="+v["payload"])
								if options.FoundAction != "" {
									foundAction(options, target, k.URL.String(), "WEAK")
								}
								resultsChan <- poc
							}
						}
					}
				}
				queryCount++
				updateSpinner(options, queryCount, len(query)+len(durls), v["param"], vStatus[v["param"]])
			}
			wg.Done()
		}()
	}

	for k, v := range query {
		queries <- Queries{request: k, metadata: v}
	}
	close(queries)
	wg.Wait()
	if !(options.Silence || options.NoSpinner) {
		s.Stop()
	}

	close(resultsChan)
	<-doneChan
	return pocs
}

// logPoC logs the PoC details and adds request/response data if configured.
func logPoC(poc *model.PoC, resbody string, req *http.Request, options model.Options, show bool, level string, message string) {
	printing.DalLog(level, message, options)
	printing.DalLog("CODE", poc.Evidence, options)
	if options.OutputRequest {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			poc.RawHTTPRequest = string(reqDump)
			printing.DalLog("CODE", "\n"+string(reqDump), options)
		}
	}
	if options.OutputResponse {
		poc.RawHTTPResponse = resbody
		printing.DalLog("CODE", string(resbody), options)
	}
	if show {
		if options.Format == "json" {
			pocj, _ := json.Marshal(poc)
			printing.DalLog("PRINT", string(pocj)+",", options)
		} else {
			pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
			printing.DalLog("PRINT", pocs, options)
		}
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
	printing.DalLog("SYSTEM", "Start Scan 🦊", options)
	if options.AllURLS > 0 {
		snow, _ := strconv.Atoi(sid)
		percent := fmt.Sprintf("%0.2f%%", float64(snow)/float64(options.AllURLS)*100)
		printing.DalLog("SYSTEM-M", "🦊 Start scan [SID:"+sid+"]["+sid+"/"+strconv.Itoa(options.AllURLS)+"]["+percent+"%] / URL: "+target, options)
	} else {
		printing.DalLog("SYSTEM-M", "🦊 Start scan [SID:"+sid+"] / URL: "+target, options)
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
