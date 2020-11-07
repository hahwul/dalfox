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
	"github.com/hahwul/dalfox/pkg/model"
	"github.com/hahwul/dalfox/pkg/optimization"
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/verification"
)

var scanObject model.Scan

// Scan is main scanning function
func Scan(target string, options model.Options, sid string) {
	printing.DalLog("SYSTEM", "Target URL: "+target, options)

	scanObject := model.Scan{
		ScanID: sid,
		URL:    target,
	}

	// query is XSS payloads
	query := make(map[*http.Request]map[string]string)

	// params is "param name":true  (reflected?)
	// 1: non-reflected , 2: reflected , 3: reflected-with-sc
	params := make(map[string][]string)

	vStatus := make(map[string]bool)
	vStatus["pleasedonthaveanamelikethis_plz_plz"] = false

	// policy is "CSP":domain..
	policy := make(map[string]string)

	// set up a rate limit
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	_, err := url.Parse(target)
	if err != nil {
		printing.DalLog("SYSTEM", "Not running "+target+" url", options)
		return
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
			return
		}
		if options.IgnoreReturn != "" {
			rcode := strings.Split(options.IgnoreReturn, ",")
			tcode := strconv.Itoa(tres.StatusCode)
			for _, v := range rcode {
				if tcode == v {
					printing.DalLog("SYSTEM", "Not running "+target+" url from --ignore-return option", options)
					return
				}
			}
		}

		defer tres.Body.Close()
		body, err := ioutil.ReadAll(tres.Body)
		printing.DalLog("SYSTEM", "Vaild target [ code:"+strconv.Itoa(tres.StatusCode)+" / size:"+strconv.Itoa(len(body))+" ]", options)
	}

	if options.Mining {
		if options.MiningWordlist != "" {
			printing.DalLog("SYSTEM", "Using dictionary mining option [list="+options.MiningWordlist+"] 📚⛏", options)
		} else {
			printing.DalLog("SYSTEM", "Using dictionary mining option [list=GF-Patterns] 📚⛏", options)
		}
	}
	if options.FindingDOM {
		printing.DalLog("SYSTEM", "Using DOM mining option 📦⛏", options)
	}

	if options.Format == "json" {
		printing.DalLog("PRINT", "[", options)
	}

	var wait sync.WaitGroup
	task := 3
	if options.NoBAV {
		task = 2
	}

	wait.Add(task)
	go func() {
		defer wait.Done()
		printing.DalLog("SYSTEM", "Start static analysis.. 🔍", options)
		policy = StaticAnalysis(target, options)
		printing.DalLog("SYSTEM", "Static analysis done ✓", options)
	}()
	go func() {
		defer wait.Done()
		printing.DalLog("SYSTEM", "Start parameter analysis.. 🔍", options)
		params = ParameterAnalysis(target, options)
		printing.DalLog("SYSTEM", "Parameter analysis  done ✓", options)
	}()
	if !options.NoBAV {
		go func() {
			defer wait.Done()
			printing.DalLog("SYSTEM", "Start BAV(Basic Another Vulnerability) analysis / [sqli, ssti, OpenRedirect]  🔍", options)
			var bavWaitGroup sync.WaitGroup
			bavTask := 3
			bavWaitGroup.Add(bavTask)
			go func() {
				defer bavWaitGroup.Done()
				SqliAnalysis(target, options)
			}()
			go func() {
				defer bavWaitGroup.Done()
				SSTIAnalysis(target, options)
			}()
			go func(){
				defer bavWaitGroup.Done()
				OpeRedirectorAnalysis(target, options)
			}()
			bavWaitGroup.Wait()
			printing.DalLog("SYSTEM", "BAV analysis done ✓", options)
		}()
	}
	
	s := spinner.New(spinner.CharSets[4], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
	s.Prefix = " "
	s.Suffix = "  Waiting routines.."
	if options.NowURL != 0 {
		s.Suffix = "  URLs(" + strconv.Itoa(options.NowURL) + " / " + strconv.Itoa(options.AllURLS) + ") :: Waiting routines"
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

		// set path base xss

		if (isAllowType(policy["Content-Type"]) && !options.OnlyCustomPayload){

			arr := getCommonPayload()
			for _, avv := range arr {

				var PathFinal string
				tmpTarget, err := url.Parse(target)
				if err != nil {
					return
				}

				if tmpTarget.Path != "" {
					PathFinal = tmpTarget.Scheme + "://" + tmpTarget.Hostname() + tmpTarget.Path
				} else {
					PathFinal = tmpTarget.Scheme + "://" + tmpTarget.Hostname() + "/" + tmpTarget.Path
				}

				tq, tm := optimization.MakeRequestQuery(PathFinal + ";" + avv, "", "", "inPATH", "toAppend", "NaN", options)
				tm["payload"] = ";" + avv
				query[tq] = tm
			}

			// set param base xss
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
									arr = getInJsPayload(ip)
								}
								if strings.Contains(ip, "inHTML") {
									arr = getHTMLPayload(ip)
								}
								if strings.Contains(ip, "inATTR") {
									arr = getAttrPayload(ip)
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
					// common XSS
					arc := getCommonPayload()
					for _, avv := range arc {
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
			for k,_ := range params {
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

		// Custom Payload
		if options.CustomPayloadFile != "" {
			ff, err := readLinesOrLiteral(options.CustomPayloadFile)
			if err != nil {
				printing.DalLog("SYSTEM", "Custom XSS payload load fail..", options)
			} else {
				for _, customPayload := range ff {
					for k, _ := range params {
						// Add plain XSS Query
						tq, tm := optimization.MakeRequestQuery(target, k, customPayload, "toHTML", "toAppend", "NaN", options)
						query[tq] = tm
						// Add URL encoded XSS Query
						etq, etm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "urlEncode",options)
						query[etq] = etm
						// Add HTML Encoded XSS Query
						htq, htm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML", "toAppend", "htmlEncode",options)
						query[htq] = htm
					}
				}
				printing.DalLog("SYSTEM", "Added your "+strconv.Itoa(len(ff))+" custom xss payload", options)
			}
		}

		printing.DalLog("SYSTEM", "Start XSS Scanning.. with "+strconv.Itoa(len(query))+" queries 🗡", options)
		s := spinner.New(spinner.CharSets[4], 100*time.Millisecond, spinner.WithWriter(os.Stderr)) // Build our new spinner
		mutex := &sync.Mutex{}
		queryCount := 0
		s.Prefix = " "
		s.Suffix = "  Make " + strconv.Itoa(options.Concurrence) + " workers and allocated " + strconv.Itoa(len(query)) + " queries"

		if !(options.Silence || options.NoSpinner) {
			s.Start() // Start the spinner
			//time.Sleep(3 * time.Second) // Run for some time to simulate work
		}
		// make waiting group
		var wg sync.WaitGroup
		// set concurrency
		concurrency := options.Concurrence
		// make reqeust channel
		queries := make(chan Queries)
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
						if containsFromArray(abs,v["payload"]) {
							vrs = true
						} else {
							vrs = false
						}
						if err == nil {
							if (v["type"] != "toBlind") && (v["type"] != "toGrepping") {
								if strings.Contains(v["type"], "inJS") {
									if vrs {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("WEAK", "Reflected Payload in JS: "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if options.Format == "json" {
												printing.DalLog("PRINT", "{\"type\":\"inJS\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
											} else {
												printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
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
								} else if strings.Contains(v["type"], "inATTR") {
									if vds {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											printing.DalLog("VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"], options)
											printing.DalLog("CODE", code, options)
											if options.Format == "json" {
												printing.DalLog("PRINT", "{\"type\":\"inATTR\",\"evidence\":\"dom verify\",\"poc\":\""+k.URL.String()+"\"},", options)
											} else {
												printing.DalLog("PRINT", "[V]["+k.Method+"] "+k.URL.String(), options)
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
											if options.Format == "json" {
												printing.DalLog("PRINT", "{\"type\":\"inATTR\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
											} else {
												printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
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
											if options.Format == "json" {
												printing.DalLog("PRINT", "{\"type\":\"inHTML\",\"evidence\":\"dom verify\",\"poc\":\""+k.URL.String()+"\"},", options)
											} else {
												printing.DalLog("PRINT", "[V]["+k.Method+"] "+k.URL.String(), options)
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
											if options.Format == "json" {
												printing.DalLog("PRINT", "{\"type\":\"inHTML\",\"evidence\":\"reflected\",\"poc\":\""+k.URL.String()+"\"},", options)
											} else {
												printing.DalLog("PRINT", "[R]["+k.Method+"] "+k.URL.String(), options)
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
							msg = "Testing \"" + v["param"] + "\" param with " + strconv.Itoa(options.Concurrence) + " worker"
						} else {
							msg = "Passing \"" + v["param"] + "\" param queries with " + strconv.Itoa(options.Concurrence) + " worker"
						}

						if options.NowURL == 0 {
							s.Suffix = "  Queries(" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + ") :: " + msg
						} else {
							s.Suffix = "  Queries(" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + "), URLs(" + strconv.Itoa(options.NowURL) + " / " + strconv.Itoa(options.AllURLS) + ") :: " + msg
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
	printing.DalLog("SYSTEM", "Finish :D", options)
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
func StaticAnalysis(target string, options model.Options) map[string]string {
	policy := make(map[string]string)
	req := optimization.GenerateNewRequest(target, "", options)
	resbody, resp, _, _, err := SendReq(req, "", options)
	if err != nil {
		return policy
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

	return policy
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, options model.Options) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	// set up a rate limit
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
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
					printing.DalLog("INFO", "Found "+strconv.Itoa(count)+" testing point in DOM Mining", options)
				}
			}
		}
	}

	var wgg sync.WaitGroup
	concurrency := options.Concurrence
	paramsQue := make(chan string)
	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			for k := range paramsQue {
				if (options.UniqParam == "") || (options.UniqParam == k) {
					//tempURL := u
					//temp_q := u.Query()
					//temp_q.Set(k, v[0]+"DalFox")
					/*
						data := u.String()
						data = strings.Replace(data, k+"="+v[0], k+"="+v[0]+"DalFox", 1)
						tempURL, _ := url.Parse(data)
						temp_q := tempURL.Query()
						tempURL.RawQuery = temp_q.Encode()
					*/
					tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA", "toAppend", "NaN", options)
					var code string

					//tempURL.RawQuery = temp_q.Encode()
					rl.Block(tempURL.Host)
					resbody, resp, _, vrs, _ := SendReq(tempURL, "DalFox", options)
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
						params[k] = append(params[k], smap)
						var wg sync.WaitGroup
						mutex := &sync.Mutex{}
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
	return params
}

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
	netTransport := getTransport(options)
	client := &http.Client{
		Timeout:   time.Duration(options.Timeout) * time.Second,
		Transport: netTransport,
	}
		
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {					
		if(strings.Contains(req.URL.Host, "google")){
			printing.DalLog("GREP", "Found Open Redirector. Payload: " + via[0].URL.String(), options)
			if options.FoundAction != "" {
				foundAction(options, via[0].Host, via[0].URL.String(), "BAV: OpenRedirect")
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
						foundAction(options, req.URL.Host, rst.PoC, "BAV: " + rst.Type)
					}

					for _, vv := range v {
						printing.DalLog("CODE", vv, options)
					}
					if options.Format == "json" {
						printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\"SSTI\",\"poc\":\""+req.URL.String()+"\"", options)
					} else {
						printing.DalLog("PRINT", "[G][SSTI/"+req.Method+"] "+req.URL.String(), options)
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
					foundAction(options, req.URL.Host, rst.PoC, "BAV: " + rst.Type)
				}

				for _, vv := range v {
					printing.DalLog("CODE", vv, options)
				}
				if options.Format == "json" {
					printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\"BUILT-IN\",\"poc\":\""+req.URL.String()+"\"", options)
				} else {
					printing.DalLog("PRINT", "[G][BUILT-IN/"+k+"/"+req.Method+"] "+req.URL.String(), options)
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
					foundAction(options, req.URL.Host, rst.PoC, "BAV: " + rst.Type)
				}

				if options.Format == "json" {
					printing.DalLog("PRINT", "\"type\":\"GREP\",\"evidence\":\""+k+"\",\"poc\":\""+req.URL.String()+"\"", options)
				} else {
					printing.DalLog("PRINT", "[G]["+k+"/"+req.Method+"] "+req.URL.String(), options)
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

		vds := verification.VerifyDOM(str)
		vrs := verification.VerifyReflection(str, payload)
		return str, resp, vds, vrs, nil

	} else {
		vds := verification.VerifyDOM(str)
		vrs := verification.VerifyReflection(str, payload)
		return str, resp, vds, vrs, nil
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
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}
