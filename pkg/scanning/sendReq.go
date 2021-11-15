package scanning

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/verification"
)

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
				if showG {
					if options.Format == "json" {
						printing.DalLog("PRINT", "{\"type\":\"GREP\",\"evidence\":\"OpenRedirect\",\"poc\":\""+via[0].URL.String()+"\"},", options)
					} else {
						printing.DalLog("PRINT", "[G][OpenRedirect/"+req.Method+"] "+via[0].URL.String(), options)
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
						printing.DalLog("PRINT", "{\"type\":\"GREP\",\"evidence\":\"CRLF\",\"poc\":\""+req.URL.String()+"\"},", options)
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
							printing.DalLog("PRINT", "{\"type\":\"GREP\",\"evidence\":\"SSTI\",\"poc\":\""+req.URL.String()+"\"},", options)
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
						printing.DalLog("PRINT", "{\"type\":\"GREP\",\"evidence\":\"BUILT-IN\",\"poc\":\""+req.URL.String()+"\"},", options)
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
						printing.DalLog("PRINT", "{\"type\":\"GREP\",\"evidence\":\""+k+"\",\"poc\":\""+req.URL.String()+"\"},", options)
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
		var method = options.Method
		options.Method = options.RequestMethod
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
