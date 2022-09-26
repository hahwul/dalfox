package scanning

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/verification"
	voltFile "github.com/hahwul/volt/file"
	vlogger "github.com/hahwul/volt/logger"
	voltUtils "github.com/hahwul/volt/util"
)

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

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, options model.Options, rl *rateLimiter) map[string][]string {
	//miningCheckerSize := 0
	miningCheckerLine := 0
	vLog := vlogger.GetLogger(options.Debug)
	pLog := vLog.WithField("data1", "PA")
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}
	var p url.Values
	var dp url.Values

	if options.Data == "" {
		p, _ = url.ParseQuery(u.RawQuery)
	} else {
		p, _ = url.ParseQuery(u.RawQuery)
		dp, _ = url.ParseQuery(options.Data)
	}

	for tempP := range p {
		params[tempP] = []string{}
	}

	if options.Mining {
		tempURL, _ := optimization.MakeRequestQuery(target, "pleasedonthaveanamelikethis_plz_plz", "DalFox", "PA", "toAppend", "NaN", options)
		rl.Block(tempURL.Host)
		resBody, _, _, vrs, _ := SendReq(tempURL, "DalFox", options)
		if vrs {
			_, lineSum := verification.VerifyReflectionWithLine(resBody, "DalFox")
			miningCheckerLine = lineSum
		}

		// Add UniqParam to Mining output
		if len(options.UniqParam) > 0 {
			for _, selectedParam := range options.UniqParam {
				p, dp = setP(p, dp, selectedParam, options)
			}
		}

		// Param mining with Gf-Patterins
		if options.MiningWordlist == "" {
			for _, gfParam := range GetGfXSS() {
				if gfParam != "" {
					p, dp = setP(p, dp, gfParam, options)
				}
			}
		} else {
			// Param mining with wordlist fil --mining-dict-word
			ff, err := voltFile.ReadLinesOrLiteral(options.MiningWordlist)
			if err != nil {
				printing.DalLog("SYSTEM", "Mining wordlist load fail..", options)
			} else {
				for _, wdParam := range ff {
					if wdParam != "" {
						p, dp = setP(p, dp, wdParam, options)
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
							p, dp = setP(p, dp, remoteWord, options)
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
				bodyString, err := ioutil.ReadAll(reader)
				if err == nil {
					body := ioutil.NopCloser(strings.NewReader(string(bodyString)))
					defer body.Close()
					doc, err := goquery.NewDocumentFromReader(body)
					if err == nil {
						count := 0
						doc.Find("input").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p, dp = setP(p, dp, name, options)
							count = count + 1
						})
						doc.Find("textarea").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p, dp = setP(p, dp, name, options)
							count = count + 1
						})
						doc.Find("select").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p, dp = setP(p, dp, name, options)
							count = count + 1
						})
						doc.Find("form").Each(func(i int, s *goquery.Selection) {
							action, _ := s.Attr("action")
							if strings.HasPrefix(action, "/") || strings.HasPrefix(action, "?") { // assuming this is a relative URL
								url, _ := url.Parse(action)
								query := url.Query()
								for aParam := range query {
									p, dp = setP(p, dp, aParam, options)
									count = count + 1
								}

							}
						})
						doc.Find("a").Each(func(i int, s *goquery.Selection) {
							href, _ := s.Attr("href")
							if strings.HasPrefix(href, "/") || strings.HasPrefix(href, "?") { // assuming this is a relative URL
								url, _ := url.Parse(href)
								query := url.Query()
								for aParam := range query {
									p, dp = setP(p, dp, aParam, options)
									count = count + 1
								}

							}
						})
						printing.DalLog("INFO", "Found "+strconv.Itoa(count)+" testing point in DOM base parameter mining", options)
					}
				}
			}
		}
	}

	// Testing URL Params
	var wgg sync.WaitGroup
	concurrency := options.Concurrence
	paramsQue := make(chan string)
	miningDictCount := 0
	waf := false
	wafName := ""
	mutex := &sync.Mutex{}
	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			for k := range paramsQue {
				if optimization.CheckInspectionParam(options, k) {
					printing.DalLog("DEBUG", "Mining URL scan to "+k, options)
					tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA", "toAppend", "NaN", options)
					var code string
					rl.Block(tempURL.Host)
					resbody, resp, _, vrs, err := SendReq(tempURL, "DalFox", options)
					if err == nil {
						wafCheck, wafN := checkWAF(resp.Header, resbody)
						if wafCheck {
							mutex.Lock()
							if !waf {
								waf = true
								wafName = wafN
								if options.WAFEvasion {
									options.Concurrence = 1
									options.Delay = 3
									printing.DalLog("INFO", "Set worker=1, delay=3s for WAF-Evasion", options)
								}
							}
							mutex.Unlock()
						}
					}
					_, lineSum := verification.VerifyReflectionWithLine(resbody, "DalFox")
					if miningCheckerLine == lineSum {
						pLog.Debug("Hit linesum")
						pLog.Debug(lineSum)
						//vrs = false
						//(#354) It can cause a lot of misconceptions. removed it.
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
						params[k] = append(params[k], "PTYPE: URL")
						params[k] = append(params[k], smap)
						mutex.Unlock()
						var wg sync.WaitGroup
						chars := GetSpecialChar()
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
										mutex.Lock()
										params[k] = append(params[k], char)
										mutex.Unlock()
									}
								}
							}()
						}
						wg.Wait()
						params[k] = voltUtils.UniqueStringSlice(params[k])
						params[k] = append(params[k], code)
					}
				}
			}
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

	// Testing Form Params
	var wggg sync.WaitGroup
	paramsDataQue := make(chan string)
	for j := 0; j < concurrency; j++ {
		wggg.Add(1)
		go func() {
			for k := range paramsDataQue {
				printing.DalLog("DEBUG", "Mining FORM scan to "+k, options)
				if optimization.CheckInspectionParam(options, k) {
					tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA-FORM", "toAppend", "NaN", options)
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
						params[k] = append(params[k], "PTYPE: FORM")
						params[k] = append(params[k], smap)
						mutex.Unlock()
						var wg sync.WaitGroup
						chars := GetSpecialChar()
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
									turl, _ := optimization.MakeRequestQuery(target, k, "dalfox"+char, "PA", "toAppend", encoder, options)
									rl.Block(tempURL.Host)
									_, _, _, vrs, _ := SendReq(turl, "dalfox"+char, options)
									_ = resp
									if vrs {
										mutex.Lock()
										params[k] = append(params[k], char)
										mutex.Unlock()
									}
								}
							}()
						}
						wg.Wait()
						params[k] = voltUtils.UniqueStringSlice(params[k])
						params[k] = append(params[k], code)
					}
				}
			}
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
		printing.DalLog("INFO", "Found "+strconv.Itoa(miningDictCount)+" testing point in Dictionary base paramter mining", options)
	}
	if waf {
		printing.DalLog("INFO", "Found WAF: "+wafName, options)
		options.WAF = true
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
	return ""
}
