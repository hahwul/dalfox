package scanning

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/verification"
	vlogger "github.com/hahwul/volt/logger"
	"github.com/sirupsen/logrus"
)

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
	vLog := vlogger.GetLogger(options.Debug)
	rLog := vLog.WithFields(logrus.Fields{
		"data1": payload,
	})
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
				poc := model.PoC{
					Type:       "G",
					InjectType: "BAV/OR",
					Method:     options.Method,
					Data:       req.URL.String(),
					Param:      "",
					Payload:    payload,
					Evidence:   "",
					CWE:        "CWE-601",
					Severity:   "Medium",
					PoCType:    options.PoCType,
				}
				if showG {
					if options.Format == "json" {
						pocj, _ := json.Marshal(poc)
						printing.DalLog("PRINT", string(pocj)+",", options)
					} else {
						pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
						printing.DalLog("PRINT", pocs, options)
					}
				}
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

	defer resp.Body.Close()
	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			reader = resp.Body
		}
		defer reader.Close()
	default:
		reader = resp.Body
	}
	bytes, err := ioutil.ReadAll(reader)
	if err == nil {
		str := string(bytes)

		//for SSTI
		ssti := getSSTIPayload()

		grepResult := make(map[string][]string)
		if !options.NoBAV {
			if len(resp.Header["Dalfoxcrlf"]) != 0 {
				poc := model.PoC{
					Type:       "G",
					InjectType: "BAV/CRLF",
					Method:     options.Method,
					Data:       req.URL.String(),
					Param:      "",
					Payload:    payload,
					Evidence:   "",
					CWE:        "CWE-93",
					Severity:   "Medium",
					PoCType:    options.PoCType,
				}
				poc.Data = MakePoC(poc.Data, req, options)

				if !duplicatedResult(scanObject.Results, poc) {
					if payload != "" {
						printing.DalLog("GREP", "Found CRLF Injection via built-in grepping / payload: "+payload, options)
					} else {
						printing.DalLog("GREP", "Found CRLF Injection via built-in grepping / original request", options)
					}
					if options.FoundAction != "" {
						foundAction(options, req.URL.Host, poc.Data, "BAV: "+poc.InjectType)
					}
					if showG {
						if options.Format == "json" {
							pocj, _ := json.Marshal(poc)
							printing.DalLog("PRINT", string(pocj)+",", options)
						} else {
							pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
							printing.DalLog("PRINT", pocs, options)
						}
					}
					scanObject.Results = append(scanObject.Results, poc)
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
					poc := model.PoC{
						Type:       "G",
						InjectType: "BAV/SSTI",
						Method:     options.Method,
						Data:       req.URL.String(),
						Param:      "",
						Payload:    payload,
						Evidence:   "",
						CWE:        "CWE-94",
						Severity:   "High",
						PoCType:    options.PoCType,
					}
					poc.Data = MakePoC(poc.Data, req, options)

					if !duplicatedResult(scanObject.Results, poc) {
						if payload != "" {
							printing.DalLog("GREP", "Found SSTI via built-in grepping / payload: "+payload, options)
						} else {
							printing.DalLog("GREP", "Found SSTI via built-in grepping / original request", options)
						}

						if options.FoundAction != "" {
							foundAction(options, req.URL.Host, poc.Data, "BAV: "+poc.InjectType)
						}

						for _, vv := range v {
							printing.DalLog("CODE", vv, options)
						}
						if showG {
							if options.Format == "json" {
								pocj, _ := json.Marshal(poc)
								printing.DalLog("PRINT", string(pocj)+",", options)
							} else {
								pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
								printing.DalLog("PRINT", pocs, options)
							}
						}
						scanObject.Results = append(scanObject.Results, poc)
					}
				}
			} else {
				// other case
				poc := model.PoC{
					Type:       "G",
					InjectType: "BUILTIN",
					Method:     options.Method,
					Data:       req.URL.String(),
					Param:      "",
					Payload:    payload,
					Evidence:   "",
					CWE:        "",
					Severity:   "Low",
					PoCType:    options.PoCType,
				}
				poc.Data = MakePoC(poc.Data, req, options)

				if !duplicatedResult(scanObject.Results, poc) {
					if payload != "" {
						printing.DalLog("GREP", "Found "+k+" via built-in grepping / payload: "+payload, options)
					} else {
						printing.DalLog("GREP", "Found "+k+" via built-in grepping / original request", options)
					}

					if options.FoundAction != "" {
						foundAction(options, req.URL.Host, poc.Data, "BAV: "+poc.InjectType)
					}

					for _, vv := range v {
						printing.DalLog("CODE", vv, options)
					}
					if showG {
						if options.Format == "json" {
							pocj, _ := json.Marshal(poc)
							printing.DalLog("PRINT", string(pocj)+",", options)
						} else {
							pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
							printing.DalLog("PRINT", pocs, options)
						}
					}
					scanObject.Results = append(scanObject.Results, poc)
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
				poc := model.PoC{
					Type:       "G",
					InjectType: "CUSTOM",
					Method:     options.Method,
					Data:       req.URL.String(),
					Param:      "",
					Payload:    payload,
					Evidence:   "",
					CWE:        "",
					Severity:   "Low",
					PoCType:    options.PoCType,
				}
				poc.Data = MakePoC(poc.Data, req, options)

				if !duplicatedResult(scanObject.Results, poc) {
					printing.DalLog("GREP", "Found "+k+" via custom grepping / payload: "+payload, options)
					for _, vv := range v {
						printing.DalLog("CODE", vv, options)
					}

					if options.FoundAction != "" {
						foundAction(options, req.URL.Host, poc.Data, "BAV: "+poc.InjectType)
					}

					if showG {
						if options.Format == "json" {
							pocj, _ := json.Marshal(poc)
							printing.DalLog("PRINT", string(pocj)+",", options)
						} else {
							pocs := "[" + poc.Type + "][" + poc.Method + "][" + poc.InjectType + "] " + poc.Data
							printing.DalLog("PRINT", pocs, options)
						}
					}
					scanObject.Results = append(scanObject.Results, poc)
				}
			}
		}

		if options.Trigger != "" {
			var treq *http.Request
			var method = options.Method
			options.Method = options.TriggerMethod
			if options.Sequence < 0 {
				treq = optimization.GenerateNewRequest(options.Trigger, "", options)
			} else {

				triggerURL := strings.Replace(options.Trigger, "SEQNC", strconv.Itoa(options.Sequence), 1)
				treq = optimization.GenerateNewRequest(triggerURL, "", options)
				options.Sequence = options.Sequence + 1
			}
			options.Method = method
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
				rLog.WithField("data2", "vds").Debug(false)
				rLog.WithField("data2", "vrs").Debug(false)
				return "", resp, false, false, err
			}

			bytes, _ := ioutil.ReadAll(resp.Body)
			str := string(bytes)

			if resp.Header["Content-Type"] != nil {
				if isAllowType(resp.Header["Content-Type"][0]) {
					vds := verification.VerifyDOM(str)
					vrs := verification.VerifyReflection(str, payload)
					rLog.WithField("data2", "vds").Debug(vds)
					rLog.WithField("data2", "vrs").Debug(vrs)
					return str, resp, vds, vrs, nil
				}
			}
			return str, resp, false, false, nil
		} else {
			if resp.Header["Content-Type"] != nil {
				if isAllowType(resp.Header["Content-Type"][0]) {
					vds := verification.VerifyDOM(str)
					vrs := verification.VerifyReflection(str, payload)
					rLog.WithField("data2", "vds").Debug(vds)
					rLog.WithField("data2", "vrs").Debug(vrs)
					return str, resp, vds, vrs, nil
				}
			}
			rLog.WithField("data2", "vds").Debug(false)
			rLog.WithField("data2", "vrs").Debug(false)
			return str, resp, false, false, nil
		}
	}
	return "", resp, false, false, err
}
