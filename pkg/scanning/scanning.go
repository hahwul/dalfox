package scanning

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/utils"
	"github.com/hahwul/dalfox/v2/internal/verification"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// performScanning performs the scanning phase by sending requests and analyzing responses.
func performScanning(target string, options model.Options, query map[*http.Request]map[string]string, durls []string, rl *rateLimiter, vStatus map[string]bool) []model.PoC {
	var pocs []model.PoC
	queryCount := 0

printing.DalLog("SYSTEM", "Starting XSS scanning with "+strconv.Itoa(len(query))+" queries", options)
printing.DalLog("SYSTEM", "[ Created "+strconv.Itoa(options.Concurrence)+" workers ] [ Allocated "+strconv.Itoa(len(query)) + " queries ]", options)

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
									printing.LogPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found dialog in headless)")
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
									printing.LogPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in JS: "+v["param"]+"="+v["payload"])
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
								printing.LogPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"])
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
								printing.LogPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in Attribute: "+v["param"]+"="+v["payload"])
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
								printing.LogPoC(&poc, resbody, k, options, showV, "VULN", "Triggered XSS Payload (found DOM Object): "+v["param"]+"="+v["payload"])
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
								printing.LogPoC(&poc, resbody, k, options, showR, "WEAK", "Reflected Payload in HTML: "+v["param"]+"="+v["payload"])
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
