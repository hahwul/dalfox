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
		if endpoint == "burp" {
			wordlist, line, size = payload.GetBurpWordlist()
		} else if endpoint == "assetnote" {
			wordlist, line, size = payload.GetAssetnoteWordlist()
		}
		if line != "" {
			printing.DalLog("INFO", "Successfully loaded '"+endpoint+"' wordlist ["+line+" lines / "+size+"]", options)
			p, dp = addParamsFromWordlist(p, dp, wordlist, options)
		}
	}
	return p, dp
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

		if options.MiningWordlist == "" {
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
	concurrency := options.Concurrence
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
	return ""
}
