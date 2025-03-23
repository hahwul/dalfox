package scanning

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/v2/internal/utils"

	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/internal/verification"
	"github.com/hahwul/dalfox/v2/pkg/model"
	vlogger "github.com/hahwul/volt/logger"
	"github.com/sirupsen/logrus"
)

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
	vLog := vlogger.GetLogger(options.Debug)
	rLog := vLog.WithFields(logrus.Fields{
		"data1": payload,
	})
	client := createHTTPClient(options)
	oReq := req

	showG := shouldShowPoC(options)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return handleRedirect(req, via, oReq, payload, options, showG)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", resp, false, false, err
	}
	defer resp.Body.Close()

	str, err := readResponseBody(resp)
	if err != nil {
		return "", resp, false, false, err
	}

	if options.Trigger != "" {
		return handleTrigger(options, payload, req, str, resp, rLog)
	}

	return processResponse(str, resp, payload, req, options, showG, rLog)
}

func shouldShowPoC(options model.Options) bool {
	if options.OnlyPoC != "" {
		showG, _, _ := printing.CheckToShowPoC(options.OnlyPoC)
		return showG
	}
	return true
}

func handleRedirect(req *http.Request, via []*http.Request, oReq *http.Request, payload string, options model.Options, showG bool) error {
	if (options.UseBAV) && (payload == "toOpenRedirecting") && !(strings.Contains(oReq.Host, ".google.com")) {
		if strings.Contains(req.URL.Host, "google.com") {
			printing.DalLog("GREP", "Found Open Redirect. Payload: "+via[0].URL.String(), options)
			poc := createPoC("BAV/OR", "CWE-601", "Medium", req, payload, options)
			poc.Data = req.URL.String()
			poc.MessageStr = "Found Open Redirect. Payload: " + via[0].URL.String()
			handlePoC(poc, req, options, showG)
		}
	}
	return nil
}

func readResponseBody(resp *http.Response) (string, error) {
	var reader io.ReadCloser
	var err error
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
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func handleTrigger(options model.Options, payload string, req *http.Request, str string, resp *http.Response, rLog *logrus.Entry) (string, *http.Response, bool, bool, error) {
	treq := generateTriggerRequest(options)
	client := createHTTPClient(options)
	resp, err := client.Do(treq)
	if err != nil {
		rLog.WithField("data2", "vds").Debug(false)
		rLog.WithField("data2", "vrs").Debug(false)
		return "", resp, false, false, err
	}
	bytes, _ := io.ReadAll(resp.Body)
	str = string(bytes)
	if resp.Header["Content-Type"] != nil && utils.IsAllowType(resp.Header["Content-Type"][0]) {
		vds := verification.VerifyDOM(str)
		vrs := verification.VerifyReflection(str, payload)
		rLog.WithField("data2", "vds").Debug(vds)
		rLog.WithField("data2", "vrs").Debug(vrs)
		return str, resp, vds, vrs, nil
	}
	return str, resp, false, false, nil
}

func generateTriggerRequest(options model.Options) *http.Request {
	var treq *http.Request
	method := options.Method
	options.Method = options.TriggerMethod
	if options.Sequence < 0 {
		treq = optimization.GenerateNewRequest(options.Trigger, "", options)
	} else {
		triggerURL := strings.Replace(options.Trigger, "SEQNC", strconv.Itoa(options.Sequence), 1)
		treq = optimization.GenerateNewRequest(triggerURL, "", options)
		options.Sequence++
	}
	options.Method = method
	return treq
}

func processResponse(str string, resp *http.Response, payload string, req *http.Request, options model.Options, showG bool, rLog *logrus.Entry) (string, *http.Response, bool, bool, error) {
	if resp.Header["Content-Type"] != nil && utils.IsAllowType(resp.Header["Content-Type"][0]) {
		vds := verification.VerifyDOM(str)
		vrs := verification.VerifyReflection(str, payload)
if !vds && options.ForceHeadlessVerification {
			// Only run headless verification if VerifyDOM failed
			vds = CheckXSSWithHeadless(req.URL.String(), options)
		}
		rLog.WithField("data2", "vds").Debug(vds)
		rLog.WithField("data2", "vrs").Debug(vrs)
		return str, resp, vds, vrs, nil
	}
	rLog.WithField("data2", "vds").Debug(false)
	rLog.WithField("data2", "vrs").Debug(false)
	return str, resp, false, false, nil
}

func createPoC(injectType, cwe, severity string, req *http.Request, payload string, options model.Options) model.PoC {
	var messageID int64

	// Safely extract the message ID from the request
	if req != nil {
		if id := req.Context().Value("message_id"); id != nil {
			// Try to convert, but don't panic if it fails
			if msgID, ok := id.(int64); ok {
				messageID = msgID
			}
		}
	}

	return model.PoC{
		Type:       "G",
		InjectType: injectType,
		Method:     options.Method,
		Data:       req.URL.String(),
		Param:      "",
		Payload:    payload,
		Evidence:   "",
		CWE:        cwe,
		Severity:   severity,
		PoCType:    options.PoCType,
		MessageID:  messageID,
	}
}

func handlePoC(poc model.PoC, req *http.Request, options model.Options, showG bool) {
	if options.OutputRequest {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			poc.RawHTTPRequest = string(reqDump)
			printing.DalLog("CODE", "\n"+string(reqDump), options)
		}
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
		foundAction(options, req.URL.Host, poc.Data, "BAV: "+poc.InjectType)
	}
}
