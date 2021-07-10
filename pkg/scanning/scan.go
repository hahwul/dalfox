package scanning

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/verification"
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
	if !(options.Silence || options.NoSpinner) {
		time.Sleep(1 * time.Second) // Waiting log
		s.Prefix = " "
		s.Suffix = ""
		if !options.NoColor {
			s.Color("red", "bold")
		}
		options.SpinnerObject = s
		s.Start()
	}

	scanObject := model.Scan{
		ScanID: sid,
		URL:    target,
	}
	if !(options.Silence && options.MulticastMode) {
		printing.DalLog("SYSTEM", "Start Scan 🦊", options)
		//printing.DalLog("SYSTEM-M", "Start Scan 🦊", options)
		if options.AllURLS > 0 {
			snow, _ := strconv.Atoi(sid)
			percent := fmt.Sprintf("%0.2f%%", float64(snow)/float64(options.AllURLS)*100)
			printing.DalLog("SYSTEM-M", "🦊 Start scan [SID:"+sid+"]["+sid+"/"+strconv.Itoa(options.AllURLS)+"]["+percent+"%] / URL: "+target, options)
		} else {
			printing.DalLog("SYSTEM-M", "🦊 Start scan [SID:"+sid+"] / URL: "+target, options)
		}
	}

	// query is XSS payloads
	query := make(map[*http.Request]map[string]string)

	// params is "param name":true  (reflected?)
	// 1: non-reflected , 2: reflected , 3: reflected-with-sc
	params := make(map[string][]string)

	// durls is url for dom xss
	var durls []string

	vStatus := make(map[string]bool)
	vStatus["pleasedonthaveanamelikethis_plz_plz"] = false

	// policy is "CSP":domain..
	policy := make(map[string]string)

	// set up a rate limit
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	parsedURL, err := url.Parse(target)
	if err != nil {
		printing.DalLog("SYSTEM", "Not running "+target+" url", options)
		return scanResult, err
	}
	treq := optimization.GenerateNewRequest(target, "", options)
	//treq, terr := http.NewRequest("GET", target, nil)
	if treq == nil {
	} else {
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

		tres, err := client.Do(treq)
		if err != nil {
			msg := fmt.Sprintf("not running %v", err)
			printing.DalLog("ERROR", msg, options)
			return scanResult, err
		}
		if options.IgnoreReturn != "" {
			rcode := strings.Split(options.IgnoreReturn, ",")
			tcode := strconv.Itoa(tres.StatusCode)
			for _, v := range rcode {
				if tcode == v {
					printing.DalLog("SYSTEM", "Not running "+target+" url from --ignore-return option", options)
					return scanResult, nil
				}
			}
		}

		defer tres.Body.Close()
		body, err := ioutil.ReadAll(tres.Body)
		printing.DalLog("SYSTEM", "Valid target [ code:"+strconv.Itoa(tres.StatusCode)+" / size:"+strconv.Itoa(len(body))+" ]", options)
	}

	if options.Format == "json" {
		printing.DalLog("PRINT", "[", options)
	}

	var wait sync.WaitGroup
	task := 3
	sa := "SA: ✓ "
	pa := "PA: ✓ "
	bav := "BAV: ✓ "
	if options.NoBAV {
		task = 2
		bav = ""
	}

	wait.Add(task)
	printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	go func() {
		defer wait.Done()
		policy, options.PathReflection = StaticAnalysis(target, options, rl)
		sa = options.AuroraObject.Green(sa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	go func() {
		defer wait.Done()
		params = ParameterAnalysis(target, options, rl)
		pa = options.AuroraObject.Green(pa).String()
		printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
	}()
	if !options.NoBAV {
		go func() {
			defer wait.Done()
			var bavWaitGroup sync.WaitGroup
			bavTask := 4
			bavWaitGroup.Add(bavTask)
			go func() {
				defer bavWaitGroup.Done()
				SqliAnalysis(target, options, rl)
			}()
			go func() {
				defer bavWaitGroup.Done()
				SSTIAnalysis(target, options, rl)
			}()
			go func() {
				defer bavWaitGroup.Done()
				OpenRedirectorAnalysis(target, options, rl)
			}()
			go func() {
				defer bavWaitGroup.Done()
				CRLFAnalysis(target, options, rl)
			}()
			bavWaitGroup.Wait()
			bav = options.AuroraObject.Green(bav).String()
			printing.DalLog("SYSTEM", "["+sa+pa+bav+"] Waiting for analysis 🔍", options)
		}()
	}

	if options.NowURL != 0 && !options.Silence {
		s.Suffix = "  [" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks] Scanning.."
	}

	if !(options.Silence || options.NoSpinner) {
		time.Sleep(1 * time.Second) // Waiting log
		s.Start()                   // Start the spinner
		//time.Sleep(3 * time.Second) // Run for some time to simulate work
	}
	wait.Wait()

	if !(options.Silence || options.NoSpinner) {
		s.Stop()
	}
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

	for k, v := range params {
		if len(v) != 0 {
			code, vv := v[len(v)-1], v[:len(v)-1]
			char := strings.Join(vv, "  ")
			//x, a = a[len(a)-1], a[:len(a)-1]
			printing.DalLog("INFO", "Reflected "+k+" param => "+char, options)
			printing.DalLog("CODE", code, options)
		}
	}

	if !options.OnlyDiscovery {
		// XSS Scanning
		printing.DalLog("SYSTEM", "Generate XSS payload and optimization.Optimization.. 🛠", options)
		// optimization.Optimization..

		/*
			k: parama name
			v: pattern [injs, inhtml, ' < > ]
			av: reflected type, valid char
		*/

		if isAllowType(policy["Content-Type"]) && !options.OnlyCustomPayload {
			// set path base XSS
			for k, v := range options.PathReflection {
				if strings.Contains(v, "Injected:") {
					// Injected pattern
					injectedPoint := strings.Split(v, "/")
					injectedPoint = injectedPoint[1:]

					for _, ip := range injectedPoint {
						var arr []string
						if strings.Contains(ip, "inJS") {
							arr = optimization.SetPayloadValue(getInJsPayload(ip), options)
						}
						if strings.Contains(ip, "inHTML") {
							arr = optimization.SetPayloadValue(getHTMLPayload(ip), options)
						}
						if strings.Contains(ip, "inATTR") {
							arr = optimization.SetPayloadValue(getAttrPayload(ip), options)
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
							// Add Path XSS Query
							tq, tm := optimization.MakeRequestQuery(tempURL, "", "", ip, "toAppend", "NaN", options)
							tm["payload"] = avv
							query[tq] = tm
						}
					}
				}
			}

			// Set common payloads
			cu, err := url.Parse(target)
			var cp url.Values
			var cpArr []string
			hashParam := false
			if err == nil {
				if options.Data == "" {
					cp, _ = url.ParseQuery(cu.RawQuery)
					if len(cp) == 0 {
						cp, _ = url.ParseQuery(cu.Fragment)
						hashParam = true
					}
				} else {
					cp, _ = url.ParseQuery(options.Data)
				}
			}

			for v := range cp {
				cpArr = append(cpArr, v)
				arc := optimization.SetPayloadValue(getCommonPayload(), options)
				for _, avv := range arc {
					// Add plain XSS Query
					tq, tm := optimization.MakeRequestQuery(target, v, avv, "inHTML", "toAppend", "NaN", options)
					query[tq] = tm
					// Add URL encoded XSS Query
					etq, etm := optimization.MakeRequestQuery(target, v, avv, "inHTML", "toAppend", "urlEncode", options)
					query[etq] = etm
					// Add HTML Encoded XSS Query
					htq, htm := optimization.MakeRequestQuery(target, v, avv, "inHTML", "toAppend", "htmlEncode", options)
					query[htq] = htm
				}
			}

			// DOM XSS payload
			var dlst []string
			if options.UseHeadless {
				if options.UseDeepDXSS {
					dlst = getDeepDOMXSPayload()
				} else {
					dlst = getDOMXSSPayload()
				}
				dpayloads := optimization.SetPayloadValue(dlst, options)
				for v := range cp {
					// loop payload list
					if len(params[v]) == 0 {
						for _, dpayload := range dpayloads {
							var durl string
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
							durl = u.String()
							durls = append(durls, durl)
						}
					}
				}
			}

			// Set param base xss
			for k, v := range params {
				vStatus[k] = false
				if (options.UniqParam == "") || (options.UniqParam == k) {
					chars := GetSpecialChar()
					var badchars []string
					for _, av := range v {
						if indexOf(av, chars) == -1 {
							badchars = append(badchars, av)
						}
						if strings.Contains(av, "Injected:") {
							// Injected pattern
							injectedPoint := strings.Split(av, "/")
							injectedPoint = injectedPoint[1:]
							for _, ip := range injectedPoint {
								var arr []string
								if strings.Contains(ip, "inJS") {
									arr = optimization.SetPayloadValue(getInJsPayload(ip), options)
								}
								if strings.Contains(ip, "inHTML") {
									arr = optimization.SetPayloadValue(getHTMLPayload(ip), options)
								}
								if strings.Contains(ip, "inATTR") {
									arr = optimization.SetPayloadValue(getAttrPayload(ip), options)
								}
								for _, avv := range arr {
									if optimization.Optimization(avv, badchars) {
										// Add plain XSS Query
										tq, tm := optimization.MakeRequestQuery(target, k, avv, ip, "toAppend", "NaN", options)
										query[tq] = tm
										// Add URL Encoded XSS Query
										etq, etm := optimization.MakeRequestQuery(target, k, avv, ip, "toAppend", "urlEncode", options)
										query[etq] = etm
										// Add HTML Encoded XSS Query
										htq, htm := optimization.MakeRequestQuery(target, k, avv, ip, "toAppend", "htmlEncode", options)
										query[htq] = htm
									}
								}
							}
						}
					}
					// common XSS for new param
					arc := optimization.SetPayloadValue(getCommonPayload(), options)
					for _, avv := range arc {
						if !containsFromArray(cpArr, k) {
							if optimization.Optimization(avv, badchars) {
								// Add plain XSS Query
								tq, tm := optimization.MakeRequestQuery(target, k, avv, "inHTML", "toAppend", "NaN", options)
								query[tq] = tm
								// Add URL encoded XSS Query
								etq, etm := optimization.MakeRequestQuery(target, k, avv, "inHTML", "toAppend", "urlEncode", options)
								query[etq] = etm
								// Add HTML Encoded XSS Query
								htq, htm := optimization.MakeRequestQuery(target, k, avv, "inHTML", "toAppend", "htmlEncode", options)
								query[htq] = htm
							}
						}
					}
				}

			}
		} else {
			printing.DalLog("SYSTEM", "Type is '"+policy["Content-Type"]+"', It does not test except customized payload (custom/blind).", options)
		}

		// Blind payload
		if options.BlindURL != "" {
			bpayloads := getBlindPayload()

			//strings.HasPrefix("foobar", "foo") // true
			var bcallback string

			if strings.HasPrefix(options.BlindURL, "https://") || strings.HasPrefix(options.BlindURL, "http://") {
				bcallback = options.BlindURL
			} else {
				bcallback = "//" + options.BlindURL
			}

			for _, bpayload := range bpayloads {
				// header base blind xss
				bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
				tq, tm := optimization.MakeHeaderQuery(target, "Referer", bp, options)
				tm["payload"] = "toBlind"
				query[tq] = tm
			}

			// loop parameter list
			for k, _ := range params {
				// loop payload list
				for _, bpayload := range bpayloads {
					// Add plain XSS Query
					bp := strings.Replace(bpayload, "CALLBACKURL", bcallback, 10)
					tq, tm := optimization.MakeRequestQuery(target, k, bp, "toBlind", "toAppend", "NaN", options)
					tm["payload"] = "toBlind"
					query[tq] = tm
					// Add URL encoded XSS Query
					etq, etm := optimization.MakeRequestQuery(target, k, bp, "toBlind", "toAppend", "urlEncode", options)
					etm["payload"] = "toBlind"
					query[etq] = etm
					// Add HTML Encoded XSS Query
					htq, htm := optimization.MakeRequestQuery(target, k, bp, "toBlind", "toAppend", "htmlEncode", options)
					htm["payload"] = "toBlind"
					query[htq] = htm
				}
			}
			printing.DalLog("SYSTEM", "Added your blind XSS ("+options.BlindURL+")", options)
		}

		// Remote Payloads
		if options.RemotePayloads != "" {
			rp := strings.Split(options.RemotePayloads, ",")
			for _, endpoint := range rp {
				var payload []string
				var line string
				var size string
				if endpoint == "portswigger" {
					payload, line, size = getPortswiggerPayload()
				}
				if endpoint == "paylaodbox" {
					payload, line, size = getPayloadBoxPayload()
				}
				if line != "" {
					printing.DalLog("INFO", "A '"+endpoint+"' payloads has been loaded ["+line+"L / "+size+"]               ", options)
					for _, customPayload := range payload {
						if customPayload != "" {
							for k, _ := range params {
								// Add plain XSS Query
								tq, tm := optimization.MakeRequestQuery(target, k, customPayload, "toHTML", "toAppend", "NaN", options)
								query[tq] = tm
								// Add URL encoded XSS Query
								etq, etm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "urlEncode", options)
								query[etq] = etm
								// Add HTML Encoded XSS Query
								htq, htm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "htmlEncode", options)
								query[htq] = htm
							}
						}
					}
				} else {
					printing.DalLog("SYSTEM", endpoint+" payload load fail..", options)
				}
			}
		}

		// Custom Payload
		if options.CustomPayloadFile != "" {
			ff, err := readLinesOrLiteral(options.CustomPayloadFile)
			if err != nil {
				printing.DalLog("SYSTEM", "Custom XSS payload load fail..", options)
			} else {
				for _, customPayload := range ff {
					if customPayload != "" {
						for k, _ := range params {
							// Add plain XSS Query
							tq, tm := optimization.MakeRequestQuery(target, k, customPayload, "toHTML", "toAppend", "NaN", options)
							query[tq] = tm
							// Add URL encoded XSS Query
							etq, etm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "urlEncode", options)
							query[etq] = etm
							// Add HTML Encoded XSS Query
							htq, htm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "htmlEncode", options)
							query[htq] = htm
						}
					}
				}
				printing.DalLog("SYSTEM", "Added your "+strconv.Itoa(len(ff))+" custom xss payload", options)
			}
		}

		printing.DalLog("SYSTEM", "Start XSS Scanning.. with "+strconv.Itoa(len(query))+" queries 🗡", options)
		mutex := &sync.Mutex{}
		queryCount := 0
		printing.DalLog("SYSTEM", "[ Make "+strconv.Itoa(options.Concurrence)+" workers ] [ Allocated "+strconv.Itoa(len(query))+" queries ]", options)

		if !(options.Silence || options.NoSpinner) {
			s.Start() // Start the spinner
			//time.Sleep(3 * time.Second) // Run for some time to simulate work
		}

		showR := false
		showV := false
		if options.OnlyPoC != "" {
			_, showR, showV = printing.CheckToShowPoC(options.OnlyPoC)
		} else {
			showR = true
			showV = true
		}

		// make waiting group
		var wg sync.WaitGroup
		// set concurrency
		concurrency := options.Concurrence
		// make reqeust channel
		queries := make(chan Queries)

		if options.UseHeadless {
			// start DOM XSS checker
			wg.Add(1)
			go func() {
				dconcurrency := options.Concurrence / 2
				if dconcurrency < 1 {
					dconcurrency = 1
				}
				dchan := make(chan string)
				var wgg sync.WaitGroup
				for i := 0; i < dconcurrency; i++ {
					wgg.Add(1)
					go func() {
						for v := range dchan {
							if CheckXSSWithHeadless(v, options) {
								mutex.Lock()
								printing.DalLog("VULN", "Triggered XSS Payload (found dialog in headless)", options)
								if showV {
									if options.Format == "json" {
										printing.DalLog("PRINT", "{\"type\":\"DOM\",\"evidence\":\"headless verify\",\"poc\":\""+v+"\"},", options)
									} else {
										printing.DalLog("PRINT", "[V][GET] "+v, options)
									}
								}
								if options.FoundAction != "" {
									foundAction(options, target, v, "VULN")
								}
								rst := &model.Issue{
									Type:  "verify code",
									Param: "DOM",
									PoC:   v,
								}
								scanObject.Results = append(scanObject.Results, *rst)
								mutex.Unlock()
							}
							queryCount = queryCount + 1
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
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				for reqJob := range queries {
					// quires.request : http.Request
					// queries.metadata : map[string]string
					k := reqJob.request
					v := reqJob.metadata

					if (vStatus[v["param"]] == false) || (v["type"] != "toBlind") || (v["type"] != "toGrepping") {
						rl.Block(k.Host)
						resbody, _, vds, vrs, err := SendReq(k, v["payload"], options)
						abs := optimization.Abstraction(resbody, v["payload"])
						if vrs {
							if !containsFromArray(abs, v["type"]) {
								vrs = false
							}
						}
						if err == nil {
							if (v["type"] != "toBlind") && (v["type"] != "toGrepping") {
								if strings.Contains(v["type"], "inJS") {
									if vrs {
										protected := false
										if verification.VerifyReflection(resbody, "\\"+v["payload"]) {
											if !strings.Contains(v["payload"], "\\") {
												protected = true
											}
										}
										if !protected {
											if vStatus[v["param"]] == false {
												if options.UseHeadless {
													if CheckXSSWithHeadless(k.URL.String(), options) {
														mutex.Lock()
														printing.DalLog("VULN", "Triggered XSS Payload (found dialog in headless)", options)
														if showV {
															if options.Format == "json" {
																printing.DalLog("PRINT", "{\"type\":\"inJS\",\"evidence\":\"headless verify\",\"poc\":\""+k.URL.String()+"\"},", options)
															} else {
																printing.DalLog("PRINT", "[V]["+k.Method+"] "+k.URL.String(), options)
															}
														}
														vStatus[v["param"]] = true
														if options.FoundAction != "" {
															foundAction(options, target, k.URL.String(), "VULN")
														}
														rst := &model.Issue{
															Type:  "verify code",
															Param: v["param"],
															PoC:   k.URL.String(),
														}
														scanObject.Results = append(scanObject.Results, *rst)
														mutex.Unlock()
													} else {
														mutex.Lock()
														if options.FoundAction != "" {
															foundAction(options, target, k.URL.String(), "WEAK")
														}
														rst := &model.Issue{
															Type:  "found code",
															Param: v["param"],
															PoC:   k.URL.String(),
														}
														scanObject.Results = append(scanObject.Results, *rst)
														mutex.Unlock()
													}
												} else {
													mutex.Lock()
													code := CodeView(resbody, v["payload"])
													printing.DalLog("WEAK", "Reflected Payload in JS: "+v["param"]+"="+v["payload"], options)
													printing.DalLog("CODE", code, options)
													if showR {
														if options.Format == "json" {
															printing.DalLog("PRINT", "{\"type\":\"inJS\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
														} else {
															printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
														}
													}
													if options.FoundAction != "" {
														foundAction(options, target, k.URL.String(), "WEAK")
													}
													rst := &model.Issue{
														Type:  "found code",
														Param: v["param"],
														PoC:   k.URL.String(),
													}
													scanObject.Results = append(scanObject.Results, *rst)
													mutex.Unlock()
												}
											}
										}
									}
								} else if strings.Contains(v["type"], "inATTR") {
									if vds {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if showV {
												if options.Format == "json" {
													printing.DalLog("PRINT", "{\"type\":\"inATTR\",\"evidence\":\"dom verify\",\"poc\":\""+k.URL.String()+"\"},", options)
												} else {
													printing.DalLog("PRINT", "[V]["+k.Method+"] "+k.URL.String(), options)
												}
											}
											vStatus[v["param"]] = true
											if options.FoundAction != "" {
												foundAction(options, target, k.URL.String(), "VULN")
											}
											rst := &model.Issue{
												Type:  "verify code",
												Param: v["param"],
												PoC:   k.URL.String(),
											}
											scanObject.Results = append(scanObject.Results, *rst)
										}
										mutex.Unlock()
									} else if vrs {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("WEAK", "Reflected Payload in Attribute: "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if showR {
												if options.Format == "json" {
													printing.DalLog("PRINT", "{\"type\":\"inATTR\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
												} else {
													poc := model.PoC{
														Type:   "R",
														Method: k.Method,
														Data:   k.URL.String(),
													}
													scanResult.PoCs = append(scanResult.PoCs, poc)
													printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
												}
											}
											if options.FoundAction != "" {
												foundAction(options, target, k.URL.String(), "WEAK")
											}
											rst := &model.Issue{
												Type:  "found code",
												Param: v["param"],
												PoC:   k.URL.String(),
											}
											scanObject.Results = append(scanObject.Results, *rst)
										}
										mutex.Unlock()
									}
								} else {
									if vds {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if showV {
												if options.Format == "json" {
													printing.DalLog("PRINT", "{\"type\":\"inHTML\",\"evidence\":\"dom verify\",\"poc\":\""+k.URL.String()+"\"},", options)
												} else {
													poc := model.PoC{
														Type:   "V",
														Method: k.Method,
														Data:   k.URL.String(),
													}
													scanResult.PoCs = append(scanResult.PoCs, poc)
													printing.DalLog("PRINT", "[V]["+k.Method+"] "+k.URL.String(), options)
												}
											}
											vStatus[v["param"]] = true
											if options.FoundAction != "" {
												foundAction(options, target, k.URL.String(), "VULN")
											}
											rst := &model.Issue{
												Type:  "verify code",
												Param: v["param"],
												PoC:   k.URL.String(),
											}
											scanObject.Results = append(scanObject.Results, *rst)
										}
										mutex.Unlock()
									} else if vrs {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("WEAK", "Reflected Payload in HTML: "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if showR {
												if options.Format == "json" {
													printing.DalLog("PRINT", "{\"type\":\"inHTML\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
												} else {
													poc := model.PoC{
														Type:   "R",
														Method: k.Method,
														Data:   k.URL.String(),
													}
													scanResult.PoCs = append(scanResult.PoCs, poc)
													printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
												}
											}
											if options.FoundAction != "" {
												foundAction(options, target, k.URL.String(), "WEAK")
											}
											rst := &model.Issue{
												Type:  "found code",
												Param: v["param"],
												PoC:   k.URL.String(),
											}
											scanObject.Results = append(scanObject.Results, *rst)
										}
										mutex.Unlock()
									}

								}
							}
						}
					}
					mutex.Lock()
					queryCount = queryCount + 1

					if !(options.Silence || options.NoSpinner) {
						s.Lock()
						var msg string
						if vStatus[v["param"]] == false {
							if options.UseHeadless {
								msg = "Testing \"" + v["param"] + "\" param and waiting headless"
							} else {
								msg = "Testing \"" + v["param"] + "\" param"
							}
						} else {
							if options.UseHeadless {
								msg = "Passing \"" + v["param"] + "\" param queries and waiting headless"
							} else {
								msg = "Passing \"" + v["param"] + "\" param queries"
							}
						}

						percent := fmt.Sprintf("%0.2f%%", (float64(queryCount)/float64(len(query)+len(durls)))*100)
						if options.NowURL == 0 {
							s.Suffix = "  [" + strconv.Itoa(queryCount) + "/" + strconv.Itoa(len(query)+len(durls)) + " Queries][" + percent + "] " + msg
						} else if !options.Silence {
							percent2 := fmt.Sprintf("%0.2f%%", (float64(options.NowURL) / float64(options.AllURLS) * 100))
							s.Suffix = "  [" + strconv.Itoa(queryCount) + "/" + strconv.Itoa(len(query)+len(durls)) + " Queries][" + percent + "][" + strconv.Itoa(options.NowURL) + "/" + strconv.Itoa(options.AllURLS) + " Tasks][" + percent2 + "] " + msg
						}
						//s.Suffix = " Waiting routines.. (" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + ") reqs"
						s.Unlock()
					}
					mutex.Unlock()
				}
				wg.Done()
			}()
		}

		// Send testing query to quires channel
		for k, v := range query {
			queries <- Queries{
				request:  k,
				metadata: v,
			}
		}
		close(queries)
		wg.Wait()
		if !(options.Silence || options.NoSpinner) {
			s.Stop()
		}
	}
	if options.Format == "json" {
		printing.DalLog("PRINT", "{}]", options)
	}
	options.Scan[sid] = scanObject
	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)
	if !(options.Silence && options.MulticastMode) {
		printing.DalLog("SYSTEM-M", "Finish Scan", options)
	}
	return scanResult, nil
}

//CodeView is showing reflected code function
func CodeView(resbody, pattern string) string {
	var code string
	if resbody == "" {
		return ""
	}
	bodyarr := strings.Split(resbody, "\n")
	for bk, bv := range bodyarr {
		if strings.Contains(bv, pattern) {
			max := len(bv)
			if max > 80 {
				index := strings.Index(bv, pattern)
				if index < 20 {
					code = code + strconv.Itoa(bk+1) + " line:  " + bv[:80] + "\n    "
				} else {
					if max < index+60 {
						code = code + strconv.Itoa(bk+1) + " line:  " + bv[index-20:max] + "\n    "
					} else {
						code = code + strconv.Itoa(bk+1) + " line:  " + bv[index-20:index+60] + "\n    "
					}
				}
			} else {
				code = code + strconv.Itoa(bk+1) + " line:  " + bv + "\n    "
			}
		}
	}
	if len(code) > 4 {
		return code[:len(code)-5]
	}
	return code
}

// StaticAnalysis is found information on original req/res
func StaticAnalysis(target string, options model.Options, rl *rateLimiter) (map[string]string, map[int]string) {
	policy := make(map[string]string)
	pathReflection := make(map[int]string)
	req := optimization.GenerateNewRequest(target, "", options)
	resbody, resp, _, _, err := SendReq(req, "", options)
	if err != nil {
		return policy, pathReflection
	}
	_ = resbody
	if resp.Header["Content-Type"] != nil {
		policy["Content-Type"] = resp.Header["Content-Type"][0]
	}
	if resp.Header["Content-Security-Policy"] != nil {
		policy["Content-Security-Policy"] = resp.Header["Content-Security-Policy"][0]
		result := checkCSP(policy["Content-Security-Policy"])
		if result != "" {
			policy["BypassCSP"] = result
		}
	}
	if resp.Header["X-Frame-Options"] != nil {
		policy["X-Frame-Options"] = resp.Header["X-Frame-Options"][0]
	}
	if resp.Header["Strict-Transport-Security"] != nil {
		policy["Strict-Transport-Security"] = resp.Header["Strict-Transport-Security"][0]
	}
	if resp.Header["Access-Control-Allow-Origin"] != nil {
		policy["Access-Control-Allow-Origin"] = resp.Header["Access-Control-Allow-Origin"][0]
	}
	paths := strings.Split(target, "/")

	// case of https://domain/ + @
	for idx, _ := range paths {
		if idx > 2 {
			id := idx - 3
			_ = id
			//var tempPath []string
			//copy(tempPath, paths)
			tempPath := strings.Split(target, "/")
			tempPath[idx] = "dalfoxpathtest"

			tempURL := strings.Join(tempPath, "/")
			req := optimization.GenerateNewRequest(tempURL, "", options)
			rl.Block(req.Host)
			resbody, _, _, vrs, err := SendReq(req, "dalfoxpathtest", options)
			if err != nil {
				return policy, pathReflection
			}
			if vrs {
				pointer := optimization.Abstraction(resbody, "dalfoxpathtest")
				smap := "Injected: "
				tempSmap := make(map[string]int)

				for _, v := range pointer {
					if tempSmap[v] == 0 {
						tempSmap[v] = 1
					} else {
						tempSmap[v] = tempSmap[v] + 1
					}
				}
				for k, v := range tempSmap {
					smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
				}
				pathReflection[id] = smap
			}
		}
	}

	// case of https://domain
	if len(paths) == 3 {

		tempURL := target + "/dalfoxpathtest"
		req := optimization.GenerateNewRequest(tempURL, "", options)
		rl.Block(req.Host)
		resbody, _, _, vrs, err := SendReq(req, "dalfoxpathtest", options)
		if err != nil {
			return policy, pathReflection
		}
		if vrs {
			pointer := optimization.Abstraction(resbody, "dalfoxpathtest")
			smap := "Injected: "
			tempSmap := make(map[string]int)

			for _, v := range pointer {
				if tempSmap[v] == 0 {
					tempSmap[v] = 1
				} else {
					tempSmap[v] = tempSmap[v] + 1
				}
			}
			for k, v := range tempSmap {
				smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
			}
			pathReflection[0] = smap
		}
	}
	return policy, pathReflection
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, options model.Options, rl *rateLimiter) map[string][]string {
	//miningCheckerSize := 0
	miningCheckerLine := 0
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}
	var p url.Values

	if options.Data == "" {
		p, _ = url.ParseQuery(u.RawQuery)
	} else {
		p, _ = url.ParseQuery(options.Data)
	}

	if options.Mining {
		tempURL, _ := optimization.MakeRequestQuery(target, "pleasedonthaveanamelikethis_plz_plz", "DalFox", "PA", "toAppend", "NaN", options)
		rl.Block(tempURL.Host)
		resBody, _, _, vrs, _ := SendReq(tempURL, "DalFox", options)
		if vrs {
			_, lineSum := verification.VerifyReflectionWithLine(resBody, "DalFox")
			miningCheckerLine = lineSum
		}
		// Param mining with Gf-Patterins
		if options.MiningWordlist == "" {
			for _, gfParam := range GetGfXSS() {
				if gfParam != "" {
					if p.Get(gfParam) == "" {
						p.Set(gfParam, "")
					}
				}
			}
		} else {
			// Param mining with wordlist fil --mining-dict-word
			ff, err := readLinesOrLiteral(options.MiningWordlist)
			if err != nil {
				printing.DalLog("SYSTEM", "Mining wordlist load fail..", options)
			} else {
				for _, wdParam := range ff {
					if wdParam != "" {
						if p.Get(wdParam) == "" {
							p.Set(wdParam, "")
						}
					}
				}
			}
		}

		if options.RemoteWordlists != "" {
			rw := strings.Split(options.RemoteWordlists, ",")
			for _, endpoint := range rw {
				var wordlist []string
				var line string
				var size string
				if endpoint == "burp" {
					wordlist, line, size = getBurpWordlist()

				}
				if endpoint == "assetnote" {
					wordlist, line, size = getAssetnoteWordlist()
				}

				if line != "" {
					printing.DalLog("INFO", "A '"+endpoint+"' wordlist has been loaded ["+line+"L / "+size+"]                   ", options)
					for _, remoteWord := range wordlist {
						if remoteWord != "" {
							if p.Get(remoteWord) == "" {
								p.Set(remoteWord, "")
							}
						}
					}
				}
			}
		}
	}

	if options.FindingDOM {
		treq := optimization.GenerateNewRequest(target, "", options)
		//treq, terr := http.NewRequest("GET", target, nil)
		if treq != nil {
			transport := getTransport(options)
			t := options.Timeout
			client := &http.Client{
				Timeout:   time.Duration(t) * time.Second,
				Transport: transport,
			}

			if !options.FollowRedirect {
				client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					//return errors.New("Follow redirect") // or maybe the error from the request
					return nil
				}
			}

			tres, err := client.Do(treq)
			if err == nil {
				defer tres.Body.Close()
				bodyString, _ := ioutil.ReadAll(tres.Body)
				body := ioutil.NopCloser(strings.NewReader(string(bodyString)))
				defer body.Close()
				doc, err := goquery.NewDocumentFromReader(body)
				if err == nil {
					count := 0
					doc.Find("input").Each(func(i int, s *goquery.Selection) {
						name, _ := s.Attr("name")
						if p.Get(name) == "" {
							p.Set(name, "")
							count = count + 1
						}
					})
					doc.Find("textarea").Each(func(i int, s *goquery.Selection) {
						name, _ := s.Attr("name")
						if p.Get(name) == "" {
							p.Set(name, "")
							count = count + 1
						}
					})
					doc.Find("select").Each(func(i int, s *goquery.Selection) {
						name, _ := s.Attr("name")
						if p.Get(name) == "" {
							p.Set(name, "")
							count = count + 1
						}
					})
					printing.DalLog("INFO", "Found "+strconv.Itoa(count)+" testing point in DOM base parameter mining", options)
				}
			}
		}
	}

	var wgg sync.WaitGroup
	concurrency := options.Concurrence
	paramsQue := make(chan string)
	miningDictCount := 0
	mutex := &sync.Mutex{}
	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			for k := range paramsQue {
				if (options.UniqParam == "") || (options.UniqParam == k) {
					tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA", "toAppend", "NaN", options)
					var code string
					rl.Block(tempURL.Host)
					resbody, resp, _, vrs, _ := SendReq(tempURL, "DalFox", options)
					_, lineSum := verification.VerifyReflectionWithLine(resbody, "DalFox")
					//fmt.Printf("%s => %d : %d\n", k, miningCheckerLine, lineSum)
					if miningCheckerLine == lineSum {
						vrs = false
					}
					if vrs {

						code = CodeView(resbody, "DalFox")
						code = code[:len(code)-5]
						pointer := optimization.Abstraction(resbody, "DalFox")
						smap := "Injected: "
						tempSmap := make(map[string]int)

						for _, v := range pointer {
							if tempSmap[v] == 0 {
								tempSmap[v] = 1
							} else {
								tempSmap[v] = tempSmap[v] + 1
							}
						}
						for k, v := range tempSmap {
							smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
						}
						mutex.Lock()
						miningDictCount = miningDictCount + 1
						params[k] = append(params[k], smap)
						mutex.Unlock()
						var wg sync.WaitGroup
						chars := GetSpecialChar()
						for _, c := range chars {
							wg.Add(1)
							char := c
							/*
								tdata := u.String()
								tdata = strings.Replace(tdata, k+"="+v[0], k+"="+v[0]+"DalFox"+char, 1)
								turl, _ := url.Parse(tdata)
								tq := turl.Query()
								turl.RawQuery = tq.Encode()
							*/

							/* turl := u
							q := u.Query()
							q.Set(k, v[0]+"DalFox"+string(char))
							turl.RawQuery = q.Encode()
							*/
							go func() {
								defer wg.Done()
								turl, _ := optimization.MakeRequestQuery(target, k, "dalfox"+char, "PA", "toAppend", "NaN", options)
								rl.Block(tempURL.Host)
								_, _, _, vrs, _ := SendReq(turl, "dalfox"+char, options)
								_ = resp
								if vrs {
									mutex.Lock()
									params[k] = append(params[k], char)
									mutex.Unlock()
								}
							}()
						}
						wg.Wait()
						params[k] = append(params[k], code)
					}
				}
			}
			wgg.Done()
		}()
	}

	for v := range p {
		paramsQue <- v
	}

	close(paramsQue)
	wgg.Wait()
	if miningDictCount != 0 {
		printing.DalLog("INFO", "Found "+strconv.Itoa(miningDictCount)+" testing point in Dictionary base paramter mining", options)
	}
	return params
}

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
	netTransport := getTransport(options)
	client := &http.Client{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Transport: netTransport,
	}
	oReq := req

	showG := false
	if options.OnlyPoC != "" {
		showG, _, _ = printing.CheckToShowPoC(options.OnlyPoC)
	} else {
		showG = true
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if (!options.NoBAV) && (payload == "toOpenRedirecting") && !(strings.Contains(oReq.Host, ".google.com")) {
			if strings.Contains(req.URL.Host, "google.com") {
				printing.DalLog("GREP", "Found Open Redirect. Payload: "+via[0].URL.String(), options)
				if options.FoundAction != "" {
					foundAction(options, via[0].Host, via[0].URL.String(), "BAV: OpenRedirect")
				}
			}
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		//fmt.Printf("HTTP call failed: %v --> %v", req.URL.String(), err)
		return "", resp, false, false, err
	}

	bytes, _ := ioutil.ReadAll(resp.Body)
	str := string(bytes)

	defer resp.Body.Close()

	//for SSTI
	ssti := getSSTIPayload()

	grepResult := make(map[string][]string)
	if !options.NoBAV {
		if len(resp.Header["Dalfoxcrlf"]) != 0 {
			rst := &model.Issue{
				Type: "Grep:CRLF",
				PoC:  req.URL.String(),
			}
			if !duplicatedResult(scanObject.Results, *rst) {
				if payload != "" {
					printing.DalLog("GREP", "Found CRLF Injection via built-in grepping / payload: "+payload, options)
				} else {
					printing.DalLog("GREP", "Found CRLF Injection via built-in grepping / original request", options)
				}
				if options.FoundAction != "" {
					foundAction(options, req.URL.Host, rst.PoC, "BAV: "+rst.Type)
				}
				if showG {
					if options.Format == "json" {
						printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\"CRLF\",\"poc\":\""+req.URL.String()+"\"", options)
					} else {
						printing.DalLog("PRINT", "[G][CRLF/"+req.Method+"] "+req.URL.String(), options)
					}
				}
				scanObject.Results = append(scanObject.Results, *rst)
			}
		}
	}
	if !options.NoGrep {
		grepResult = builtinGrep(str)
	}
	for k, v := range grepResult {
		if k == "dalfox-ssti" {
			really := false
			for _, vv := range ssti {
				if vv == payload {
					really = true
				}
			}

			if really {
				rst := &model.Issue{
					Type: "Grep:SSTI",
					PoC:  req.URL.String(),
				}
				if !duplicatedResult(scanObject.Results, *rst) {
					if payload != "" {
						printing.DalLog("GREP", "Found SSTI via built-in grepping / payload: "+payload, options)
					} else {
						printing.DalLog("GREP", "Found SSTI via built-in grepping / original request", options)
					}

					if options.FoundAction != "" {
						foundAction(options, req.URL.Host, rst.PoC, "BAV: "+rst.Type)
					}

					for _, vv := range v {
						printing.DalLog("CODE", vv, options)
					}
					if showG {
						if options.Format == "json" {
							printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\"SSTI\",\"poc\":\""+req.URL.String()+"\"", options)
						} else {
							printing.DalLog("PRINT", "[G][SSTI/"+req.Method+"] "+req.URL.String(), options)
						}
					}
					scanObject.Results = append(scanObject.Results, *rst)
				}
			}
		} else {
			// other case
			rst := &model.Issue{
				Type: "Grep:" + k,
				PoC:  req.URL.String(),
			}
			if !duplicatedResult(scanObject.Results, *rst) {
				if payload != "" {
					printing.DalLog("GREP", "Found "+k+" via built-in grepping / payload: "+payload, options)
				} else {
					printing.DalLog("GREP", "Found "+k+" via built-in grepping / original request", options)
				}

				if options.FoundAction != "" {
					foundAction(options, req.URL.Host, rst.PoC, "BAV: "+rst.Type)
				}

				for _, vv := range v {
					printing.DalLog("CODE", vv, options)
				}
				if showG {
					if options.Format == "json" {
						printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\"BUILT-IN\",\"poc\":\""+req.URL.String()+"\"", options)
					} else {
						printing.DalLog("PRINT", "[G][BUILT-IN/"+k+"/"+req.Method+"] "+req.URL.String(), options)
					}
				}
				scanObject.Results = append(scanObject.Results, *rst)
			}
		}
	}

	if options.Grep != "" {
		pattern := make(map[string]string)
		var result map[string]interface{}
		json.Unmarshal([]byte(options.Grep), &result)
		for k, v := range result {
			pattern[k] = v.(string)
		}
		cg := customGrep(str, pattern)
		for k, v := range cg {
			rst := &model.Issue{
				Type: "Grep:" + k,
				PoC:  req.URL.String(),
			}
			if !duplicatedResult(scanObject.Results, *rst) {
				printing.DalLog("GREP", "Found "+k+" via custom grepping / payload: "+payload, options)
				for _, vv := range v {
					printing.DalLog("CODE", vv, options)
				}

				if options.FoundAction != "" {
					foundAction(options, req.URL.Host, rst.PoC, "BAV: "+rst.Type)
				}

				if showG {
					if options.Format == "json" {
						printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\""+k+"\",\"poc\":\""+req.URL.String()+"\"", options)
					} else {
						printing.DalLog("PRINT", "[G]["+k+"/"+req.Method+"] "+req.URL.String(), options)
					}
				}
				scanObject.Results = append(scanObject.Results, *rst)
			}
		}
	}

	if options.Trigger != "" {
		var treq *http.Request
		if options.Sequence < 0 {
			treq = optimization.GenerateNewRequest(options.Trigger, "", options)
		} else {

			triggerURL := strings.Replace(options.Trigger, "SEQNC", strconv.Itoa(options.Sequence), 1)
			treq = optimization.GenerateNewRequest(triggerURL, "", options)
			options.Sequence = options.Sequence + 1
		}
		netTransport := getTransport(options)
		client := &http.Client{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			Transport: netTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("something bad happened") // or maybe the error from the request
			},
		}
		resp, err := client.Do(treq)
		if err != nil {
			return "", resp, false, false, err
		}

		bytes, _ := ioutil.ReadAll(resp.Body)
		str := string(bytes)

		if resp.Header["Content-Type"] != nil {
			if isAllowType(resp.Header["Content-Type"][0]) {
				vds := verification.VerifyDOM(str)
				vrs := verification.VerifyReflection(str, payload)
				return str, resp, vds, vrs, nil
			}
		}
		return str, resp, false, false, nil
	} else {
		if resp.Header["Content-Type"] != nil {
			if isAllowType(resp.Header["Content-Type"][0]) {
				vds := verification.VerifyDOM(str)
				vrs := verification.VerifyReflection(str, payload)
				return str, resp, vds, vrs, nil
			}
		}
		return str, resp, false, false, nil
	}
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}

func duplicatedResult(result []model.Issue, rst model.Issue) bool {
	for _, v := range result {
		if v.Type == rst.Type {
			return true
		}
	}
	return false
}

func containsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	t := strings.Split(item, "(")
	i := t[0]
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[i]
	return ok
}
